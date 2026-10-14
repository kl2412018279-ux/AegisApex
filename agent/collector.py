# agent/collector.py
#
# SSH collection and change application for every supported platform.
# Used by worker.py (job queue) and runnable directly:
#
#   python collector.py                  # every active device, once
#   python collector.py --device-id ID   # one device
import argparse
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from dotenv import load_dotenv
from netmiko import ConnectHandler
from supabase import Client, create_client

import hostkeys

BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("collector")

load_dotenv(BASE_DIR / ".env")

SUPABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL")
# Service role only. There is deliberately no fallback to the public anon key.
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")

# Paging-disable, config and version commands per Netmiko device_type.
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

# Platforms where configuration changes only take effect after a commit.
COMMIT_PLATFORMS = {"juniper_junos", "cisco_xr", "paloalto_panos", "vyos", "nokia_sros"}


class CollectionError(Exception):
    pass


def get_supabase_client() -> Client:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in agent/.env.")
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def fetch_decrypted_credentials(device_id: str, supabase: Client) -> dict:
    try:
        res = supabase.rpc("get_device_credentials", {"p_device_id": device_id}).execute()
        if res.data:
            return res.data[0]
    except Exception as e:
        log.warning(f"Vault RPC error for device {device_id}: {e}")
    return {}


_VERSION_PATTERNS = [
    r"junos:?\s*([0-9]+\.[0-9]+[0-9A-Za-z.\-]*)",
    r"sw-version:\s*([0-9]+\.[0-9]+[0-9A-Za-z.\-]*)",
    r"fortigate[^\n]*?v([0-9]+\.[0-9]+\.[0-9]+)",
    r"version:\s*v?([0-9]+\.[0-9]+[0-9A-Za-z.\-]*)",
    r"(?:version|v)\s*([0-9]+\.[0-9]+[0-9a-zA-Z.()\-_]*)",
]


def extract_clean_os_version(raw_version_text: str) -> str:
    if not raw_version_text:
        return ""
    for pattern in _VERSION_PATTERNS:
        match = re.search(pattern, raw_version_text, re.IGNORECASE)
        if match:
            return match.group(1).rstrip(",.")
    return ""


def device_host(device: dict) -> str:
    return device.get("management_ip") or device.get("ip_address") or ""


@contextmanager
def open_session(device: dict, supabase: Client) -> Iterator[object]:
    """Opens an authenticated, host-key-verified Netmiko session."""
    device_id = device["id"]
    host = device_host(device)
    if not host:
        raise CollectionError("Device has no management IP configured.")

    creds = fetch_decrypted_credentials(device_id, supabase)
    username = creds.get("ssh_user") or device.get("ssh_user")
    password = creds.get("ssh_pass") or ""
    if not password:
        raise CollectionError("No SSH password found in Vault for this device.")
    if not username:
        raise CollectionError("No SSH username in Vault or on the devices row (ssh_user). Refusing to guess one.")

    port = int(device.get("ssh_port") or 22)
    pinned = hostkeys.ensure_pinned(device, host, port, supabase)
    if pinned.newly_pinned:
        log.info(f"Pinned SSH host key for {host}: {pinned.fingerprint} (trust on first use)")
    known_hosts = hostkeys.write_known_hosts(host, port, pinned)

    params = {
        "device_type": device.get("netmiko_type") or "cisco_xe",
        "host": host,
        "username": username,
        "password": password,
        "secret": creds.get("enable_pass") or password,
        "port": port,
        "timeout": 30,
        "auth_timeout": 60,
        "fast_cli": False,
        # 2 rather than 1: slower but safer on congested or VPN-tunneled
        # out-of-band management links.
        "global_delay_factor": 2,
        **hostkeys.strict_connection_params(known_hosts),
    }
    conn = None
    try:
        conn = ConnectHandler(**params)
        try:
            conn.enable()
        except Exception as e:
            log.debug(f"Enable mode not entered on {host}: {e}")
        paging = VENDOR_COMMAND_MAP.get(params["device_type"], VENDOR_COMMAND_MAP["cisco_ios"]).get("paging")
        if paging:
            conn.send_command(paging)
        yield conn
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass
        os.unlink(known_hosts)


def capture(conn, netmiko_type: str) -> tuple:
    cmds = VENDOR_COMMAND_MAP.get(netmiko_type, VENDOR_COMMAND_MAP["cisco_ios"])
    raw_version = conn.send_command(cmds["version"]) if cmds.get("version") else ""
    raw_config = conn.send_command(cmds["config"])
    if not raw_config or len(raw_config.strip()) < 15:
        raise CollectionError("Device returned an empty or truncated configuration.")
    return raw_version, raw_config


def store_snapshot(
    supabase: Client,
    device: dict,
    raw_config: str,
    raw_version: str,
    source: str = "ssh",
    current: bool = True,
) -> Optional[str]:
    """
    Saves a config snapshot. When `current`, it also becomes the device's
    latest state (devices row + an UNASSESSED scans row). Returns the id.
    """
    ts = now_iso()
    config_res = supabase.table("configurations").insert({
        "device_id": device["id"],
        "raw_config": raw_config,
        "content": raw_config,
        "source": source,
        "created_at": ts,
    }).execute()
    configuration_id = config_res.data[0]["id"] if config_res.data else None
    if not current:
        return configuration_id

    update = {
        "connection_status": "online",
        "last_seen_at": ts,
        "last_config": raw_config,
        "raw_version": raw_version,
        "last_collection_error": None,
    }
    clean_version = extract_clean_os_version(raw_version)
    if clean_version:
        update["os_version"] = clean_version
    try:
        supabase.table("devices").update(update).eq("id", device["id"]).execute()
    except Exception as e:
        log.warning(f"Device update failed ({e}); retrying without os_version")
        update.pop("os_version", None)
        supabase.table("devices").update(update).eq("id", device["id"]).execute()

    if configuration_id:
        try:
            supabase.table("scans").insert({
                "device_id": device["id"],
                "configuration_id": configuration_id,
                "raw_version": raw_version,
                "summary": f"Telemetry collected via SSH at {ts}",
                "risk_level": "UNASSESSED",
                "created_at": ts,
            }).execute()
        except Exception as e:
            log.warning(f"Scan record insert failed for {device['id']}: {e}")
    return configuration_id


def raise_alert(supabase: Client, device: dict, kind: str, severity: str, title: str, body: str) -> None:
    """Queues an alert; the dashboard's /api/cron/process delivers it."""
    try:
        supabase.table("alert_events").insert({
            "org_id": device.get("org_id"),
            "device_id": device["id"],
            "kind": kind,
            "severity": severity,
            "title": title,
            "body": body,
        }).execute()
    except Exception as e:
        log.error(f"Could not queue {kind} alert for {device['id']}: {e}")


def mark_unreachable(supabase: Client, device: dict, exc: BaseException) -> str:
    host_key_message = hostkeys.describe_failure(exc)
    message = host_key_message or f"{type(exc).__name__}: {exc}"
    was_unreachable = device.get("connection_status") == "unreachable"
    try:
        supabase.table("devices").update({
            "connection_status": "unreachable",
            "last_collection_error": message[:1000],
        }).eq("id", device["id"]).execute()
    except Exception as db_err:
        log.error(f"Failed to set unreachable status for {device['id']}: {db_err}")

    name = device.get("hostname") or device_host(device)
    if host_key_message:
        raise_alert(supabase, device, "host_key_mismatch", "CRITICAL", f"SSH host key problem on {name}", message)
    elif not was_unreachable:
        raise_alert(supabase, device, "device_unreachable", "HIGH", f"{name} is unreachable", message)
    return message


def collect_device(device: dict, supabase: Client) -> dict:
    """Collects one device. Raises on failure (caller marks it unreachable)."""
    log.info(f"Collecting {device_host(device)} ({device.get('netmiko_type')}, {device['id']})")
    with open_session(device, supabase) as conn:
        raw_version, raw_config = capture(conn, device.get("netmiko_type") or "cisco_xe")
    configuration_id = store_snapshot(supabase, device, raw_config, raw_version)
    log.info(f"Collection complete for {device_host(device)}")
    return {"configuration_id": configuration_id}


def apply_commands(device: dict, supabase: Client, commands: list, save: bool = True) -> dict:
    """
    Pushes configuration commands, then snapshots the config before and after
    so the change can be verified and diffed. Returns the device output.
    """
    netmiko_type = device.get("netmiko_type") or "cisco_xe"
    with open_session(device, supabase) as conn:
        _, pre_config = capture(conn, netmiko_type)
        output = conn.send_config_set(commands, exit_config_mode=netmiko_type not in COMMIT_PLATFORMS)
        if netmiko_type in COMMIT_PLATFORMS:
            output += "\n" + conn.commit()
            conn.exit_config_mode()
        elif save:
            try:
                output += "\n" + conn.save_config()
            except NotImplementedError:
                output += "\n[agent] save_config is not supported on this platform; change is in the running config only."
        raw_version, post_config = capture(conn, netmiko_type)

    pre_id = store_snapshot(supabase, device, pre_config, raw_version, source="ssh", current=False)
    post_id = store_snapshot(supabase, device, post_config, raw_version, source="post_remediation")
    return {"output": output, "pre_configuration_id": pre_id, "post_configuration_id": post_id}


def process_device(device: dict) -> bool:
    supabase = get_supabase_client()
    try:
        collect_device(device, supabase)
        return True
    except Exception as e:
        message = mark_unreachable(supabase, device, e)
        log.error(f"Collection failed for {device_host(device)} ({device['id']}): {message}")
        return False


def run_collector(target_device_id: Optional[str] = None, max_workers: int = 5) -> tuple:
    supabase = get_supabase_client()
    query = supabase.table("devices").select("*").eq("is_mock", False)
    query = query.eq("id", target_device_id) if target_device_id else query.neq("connection_status", "inactive")
    devices = query.execute().data or []
    if not devices:
        log.info("No target devices found to collect.")
        return 0, 0

    log.info(f"Collecting {len(devices)} device(s) with {max_workers} worker(s)...")
    succeeded = failed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_device, d): d for d in devices}
        for future in as_completed(futures):
            device = futures[future]
            try:
                ok = future.result()
            except Exception as e:  # process_device handles its own errors; this is a bug guard
                log.exception(f"Unexpected error collecting {device['id']}: {e}")
                ok = False
            succeeded += ok
            failed += not ok
    log.info(f"Collection finished: {succeeded} succeeded, {failed} failed.")
    return succeeded, failed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisApex Collector")
    parser.add_argument("--device-id", type=str, help="Target a specific device UUID")
    parser.add_argument("--workers", type=int, default=5)
    args = parser.parse_args()
    _, failures = run_collector(target_device_id=args.device_id, max_workers=args.workers)
    raise SystemExit(1 if failures else 0)
