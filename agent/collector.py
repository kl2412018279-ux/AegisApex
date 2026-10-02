# agent/collector.py
#
# Merged from your original collector.py and the Gemini-refactored version
# you asked me to compare it against. Kept:
#   - your paging-disable commands and global_delay_factor=2 (original) —
#     dropping these is a real hardware-behavior change I can't verify
#     against your actual fleet, so I did not adopt Gemini's removal of them
#   - Gemini's Supabase-key fallback fix (no silent anon-key fallback)
#   - Gemini's single-client-per-device pattern (was up to 5 instantiations
#     per device in the original)
#   - Gemini's logged (not swallowed) error on the offline-status write
# Fixed beyond both versions:
#   - the "admin" hardcoded username fallback is gone; a device with no
#     resolvable username now fails loudly instead of guessing
#   - ssh_user is resolved from the vault RPC result AND the devices table
#     (matches your actual schema: ssh_user lives directly on `devices`,
#     only the passwords are vaulted) — Gemini's version dropped the
#     devices-table fallback entirely, which would silently connect as
#     "admin" on any device with a real username set on its row but not
#     returned by the RPC
#   - devices.raw_version is written again (Gemini's version dropped it;
#     your dashboard reads raw_version primarily from `scans`, but a
#     future fleet-wide version report reading `devices` alone would see
#     blanks without this)
import os
import sys
import re
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from supabase import create_client, Client
from netmiko import ConnectHandler

BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("collector")

# Load environment variables — agent/.env only. If you were relying on the
# original's 4-location cascade (repo root / dashboard/.env.local /
# dashboard/.env), make sure agent/.env has everything it needs; see
# agent/.env.example.
load_dotenv(BASE_DIR / ".env")

SUPABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL")
# FIX: no anon-key fallback. The original's fallback chain ended at
# NEXT_PUBLIC_SUPABASE_ANON_KEY — the SAME key shipped in the dashboard's
# browser bundle. If SUPABASE_SERVICE_ROLE_KEY was ever unset, the agent
# would silently run under the public key instead of failing loudly. If
# get_device_credentials() has EXECUTE granted to anon/authenticated (check
# this — see the SQL file in this delivery), that fallback could let this
# same "credential" be used by anyone with the public key, not just the
# agent. Missing the service key is now a hard failure, not a silent
# downgrade.
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")

# Multi-Vendor Command Matrix (Config & OS Telemetry).
# Kept from the original: the paging-disable command per vendor. Netmiko
# auto-disables paging for many of its built-in device_types during
# connection setup, but I can't confirm that holds for all 19 entries here
# without testing against real hardware of each type — if this dict was
# added because you hit a real truncation issue on some device, removing it
# (as the Gemini refactor did) would silently reintroduce that bug. Left in.
VENDOR_COMMAND_MAP = {
    "cisco_ios": {"paging": "terminal length 0", "config": "show running-config", "version": "show version"},
    "cisco_xe": {"paging": "terminal length 0", "config": "show running-config", "version": "show version"},
    "cisco_nxos": {"paging": "terminal length 0", "config": "show running-config", "version": "show version"},
    "cisco_xr": {"paging": "terminal length 0", "config": "show running-config", "version": "show version"},
    "arista_eos": {"paging": "terminal length 0", "config": "show running-config", "version": "show version"},
    "juniper_junos": {"paging": "set cli screen-length 0", "config": "show configuration", "version": "show version"},
    "paloalto_panos": {"paging": "set cli pager off", "config": "show config running", "version": "show system info"},
    "fortinet": {"paging": None, "config": "show full-configuration", "version": "get system status"},
    "huawei": {"paging": "screen-length 0 temporary", "config": "display current-configuration", "version": "display version"},
    "huawei_vrp": {"paging": "screen-length 0 temporary", "config": "display current-configuration", "version": "display version"},
    "aruba_os": {"paging": "no page", "config": "show running-config", "version": "show version"},
    "aruba_osswitch": {"paging": "no page", "config": "show running-config", "version": "show version"},
    "hp_comware": {"paging": "screen-length 0 temporary", "config": "display current-configuration", "version": "display version"},
    "dell_os10": {"paging": "terminal length 0", "config": "show running-configuration", "version": "show version"},
    "f5_tmsh": {"paging": "modify cli preference pager disabled", "config": "list sys config", "version": "show sys version"},
    "nokia_sros": {"paging": "environment more false", "config": "admin display-config", "version": "show version"},
    "vyos": {"paging": "set terminal length 0", "config": "show configuration", "version": "show version"},
    "extreme_exos": {"paging": "disable clipaging", "config": "show configuration", "version": "show version"},
    "mikrotik_routeros": {"paging": None, "config": "/export", "version": "/system resource print"},
}


def get_supabase_client() -> Client:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError(
            "Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in agent/.env. "
            "The agent will not fall back to an anon key — see the comment above SUPABASE_KEY."
        )
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def fetch_decrypted_credentials(device_id: str, supabase: Client) -> dict:
    try:
        rpc_res = supabase.rpc("get_device_credentials", {"p_device_id": device_id}).execute()
        if rpc_res.data and len(rpc_res.data) > 0:
            return rpc_res.data[0]
    except Exception as e:
        log.warning(f"RPC Vault error for device {device_id}: {e}")
    return {}


def extract_clean_os_version(raw_version_text: str) -> str:
    if not raw_version_text:
        return ""
    match = re.search(r'(?:version|v|junos:?)\s*([0-9]+\.[0-9]+[0-9a-zA-Z\.\(\)\-\_]*)', raw_version_text, re.IGNORECASE)
    return match.group(1) if match else ""


def process_device(device: dict):
    # FIX (Gemini's improvement, adopted): one client per device instead of
    # the original's up to 5 separate instantiations (config write, status
    # write, raw_version write, scan write, error write).
    supabase = get_supabase_client()

    device_id = device.get("id")
    device_ip = device.get("management_ip") or device.get("ip_address")
    netmiko_type = device.get("netmiko_type") or "cisco_xe"

    vault_creds = fetch_decrypted_credentials(device_id, supabase)

    # FIX: username resolution now checks the vault RPC result AND the
    # devices table (your schema stores ssh_user directly on `devices` —
    # it's not secret, only the passwords are vaulted). Gemini's version
    # checked only the RPC result; if get_device_credentials() doesn't
    # happen to return ssh_user, that version would silently try "admin"
    # even for a device with a real username set on its row. And unlike
    # both prior versions, a device with a password but genuinely no
    # resolvable username now fails loudly instead of guessing "admin".
    username = vault_creds.get("ssh_user") or device.get("ssh_user")
    password = vault_creds.get("ssh_pass") or ""
    secret = vault_creds.get("enable_pass") or password
    ssh_port = device.get("ssh_port") or 22

    if not password:
        log.info(f"Skipped {device_ip} ({device_id}): no SSH password found in Vault.")
        return

    if not username:
        log.warning(
            f"Skipped {device_ip} ({device_id}): no SSH username found in Vault or on the "
            f"devices row (ssh_user). Refusing to guess a default credential — set ssh_user "
            f"on the device or return it from get_device_credentials()."
        )
        return

    log.info(f"Starting collection for {device_ip} (Vendor: {netmiko_type}, ID: {device_id})")

    try:
        connection_params = {
            "device_type": netmiko_type,
            "host": device_ip,
            "username": username,
            "password": password,
            "secret": secret,
            "port": ssh_port,
            "timeout": 30,
            "auth_timeout": 60,
            "fast_cli": False,
            # Kept at 2 (original), not lowered to 1 (Gemini). Halving this
            # halves Netmiko's internal wait/read timers — fine on healthy
            # low-latency links, more likely to mistime reads on slow,
            # congested, or VPN-tunneled out-of-band management connections.
            # If your whole fleet is reliably low-latency, 1 is safe and
            # faster; verify before lowering it.
            "global_delay_factor": 2,
        }

        net_connect = ConnectHandler(**connection_params)

        if hasattr(net_connect, "enable"):
            try:
                net_connect.enable()
            except Exception as e:
                log.warning(f"Enable mode warning for {device_ip}: {e}")

        cmd_info = VENDOR_COMMAND_MAP.get(netmiko_type, VENDOR_COMMAND_MAP["cisco_ios"])
        if cmd_info.get("paging"):
            net_connect.send_command(cmd_info["paging"])

        # 1. Collect OS / Firmware Version Telemetry
        raw_version = ""
        if cmd_info.get("version"):
            raw_version = net_connect.send_command(cmd_info["version"])

        # 2. Collect Running Configuration Telemetry
        raw_config = net_connect.send_command(cmd_info["config"])
        net_connect.disconnect()

        if not raw_config or len(raw_config.strip()) < 15:
            log.warning(f"Empty or invalid config received for device {device_id}. Skipping.")
            return

        now_iso = datetime.now(timezone.utc).isoformat()
        clean_version = extract_clean_os_version(raw_version)

        # 3. Write snapshot into configurations table
        config_payload = {
            "device_id": device_id,
            "raw_config": raw_config,
            "content": raw_config,
            "created_at": now_iso,
        }
        config_res = supabase.table("configurations").insert(config_payload).execute()
        log.info(f"Configuration snapshot saved for {device_ip}")

        # 4. Synchronize device status, running config, and OS telemetry
        device_update = {
            "connection_status": "online",
            "last_seen_at": now_iso,
            "last_config": raw_config,
        }
        if clean_version:
            device_update["os_version"] = clean_version

        try:
            supabase.table("devices").update(device_update).eq("id", device_id).execute()
            log.info(f"Status, last_config & OS Version ({clean_version or 'raw'}) updated for {device_ip}")
        except Exception:
            # Fallback if os_version column is named differently in your schema
            device_update.pop("os_version", None)
            supabase.table("devices").update(device_update).eq("id", device_id).execute()
            log.info(f"Status & last_config updated for {device_ip} (os_version update skipped)")

        # 5. raw_version on the devices row (kept from the original; Gemini's
        # version dropped this — the dashboard mostly reads raw_version from
        # `scans`, but a fleet-wide report querying `devices` alone would
        # otherwise see this column blank per-device).
        try:
            supabase.table("devices").update({"raw_version": raw_version}).eq("id", device_id).execute()
        except Exception as e:
            log.warning(f"Could not write raw_version for {device_ip}: {e}")

        # 6. Insert scan record so the dashboard's polling succeeds
        configuration_id = config_res.data[0].get("id") if config_res.data else None
        scan_payload = {
            "device_id": device_id,
            "configuration_id": configuration_id,
            "raw_version": raw_version,
            "summary": f"Telemetry collected successfully via SSH on {now_iso}",
            "risk_level": "UNASSESSED",
            "created_at": now_iso,
        }
        try:
            supabase.table("scans").insert(scan_payload).execute()
            log.info(f"Scan telemetry event inserted for {device_ip}")
        except Exception as scan_err:
            log.warning(f"Failed to insert scan event record for {device_ip}: {scan_err}")

        log.info(f"Collection complete for {device_ip}")

    except Exception as e:
        log.error(f"SSH or ingestion error for device {device_ip} ({device_id}): {e}")
        try:
            # FIX (Gemini's improvement, adopted): logged, not silently
            # swallowed — the original's bare `except: pass` here meant a
            # failure to even mark a device offline left no trace anywhere.
            supabase.table("devices").update({"connection_status": "offline"}).eq("id", device_id).execute()
        except Exception as db_err:
            log.error(f"Failed to set offline status for {device_ip}: {db_err}")


def run_collector(target_device_id: str = None, max_workers: int = 5):
    supabase = get_supabase_client()

    query = supabase.table("devices").select("*")
    if target_device_id:
        query = query.eq("id", target_device_id)
    else:
        query = query.neq("connection_status", "inactive")

    response = query.execute()
    devices = response.data or []

    if not devices:
        log.info("No target devices found to collect.")
        return

    log.info(f"Launching collection for {len(devices)} device(s) across {max_workers} worker(s)...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # NOTE (unchanged from both prior versions): executor.map() does not
        # raise exceptions from worker threads until the results are
        # iterated, and results here are never iterated — so an exception
        # inside process_device() for one device is currently swallowed by
        # the executor itself, on top of the try/except already inside
        # process_device(). That inner try/except is what actually protects
        # you today; this is noted for awareness, not changed, since
        # iterating results to surface exceptions is a slightly bigger
        # behavior change than the rest of this pass.
        executor.map(process_device, devices)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisApex Collector")
    parser.add_argument("--device-id", type=str, help="Target a specific device UUID")
    args = parser.parse_args()

    run_collector(target_device_id=args.device_id, max_workers=5)
