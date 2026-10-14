# agent/hostkeys.py
#
# SSH host key pinning. Netmiko's default (ssh_strict=False) auto-accepts any
# host key, so anyone on the path between the agent and a device could
# impersonate it and capture the admin password. Instead:
#
#   * first contact: fetch the device's key and pin it on the devices row
#     (trust on first use). Set AEGIS_REQUIRE_PINNED_HOST_KEYS=true to refuse
#     unpinned devices entirely and pin keys out of band instead.
#   * every later connection: Netmiko runs with ssh_strict=True against a
#     known_hosts file containing only the pinned key, so a changed key is
#     rejected before authentication.
import base64
import hashlib
import os
import socket
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import paramiko


class HostKeyError(Exception):
    """The device presented a host key we can't trust."""


@dataclass
class PinnedKey:
    key_type: str
    key_b64: str
    fingerprint: str
    newly_pinned: bool = False


def fingerprint_sha256(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def fetch_host_key(host: str, port: int, timeout: float = 10.0) -> paramiko.PKey:
    sock = socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        transport.close()


def known_hosts_entry(host: str, port: int, key_type: str, key_b64: str) -> str:
    name = host if port == 22 else f"[{host}]:{port}"
    return f"{name} {key_type} {key_b64}\n"


def write_known_hosts(host: str, port: int, pinned: PinnedKey) -> str:
    """Writes a one-entry known_hosts file and returns its path (caller deletes it)."""
    fd, path = tempfile.mkstemp(prefix="aegis_known_hosts_")
    with os.fdopen(fd, "w") as fh:
        fh.write(known_hosts_entry(host, port, pinned.key_type, pinned.key_b64))
    return path


def require_prepinned() -> bool:
    return os.getenv("AEGIS_REQUIRE_PINNED_HOST_KEYS", "").lower() in ("1", "true", "yes")


def ensure_pinned(device: dict, host: str, port: int, supabase, fetch=fetch_host_key) -> PinnedKey:
    """Returns the pinned key for a device, pinning it on first contact."""
    if device.get("ssh_host_key") and device.get("ssh_host_key_type"):
        key_bytes = base64.b64decode(device["ssh_host_key"])
        return PinnedKey(device["ssh_host_key_type"], device["ssh_host_key"], fingerprint_sha256(key_bytes))

    if require_prepinned():
        raise HostKeyError(
            f"No pinned SSH host key for {host} and AEGIS_REQUIRE_PINNED_HOST_KEYS is set. "
            "Pin the key on the devices row (ssh_host_key_type / ssh_host_key) before collecting."
        )

    key = fetch(host, port)
    pinned = PinnedKey(key.get_name(), key.get_base64(), fingerprint_sha256(key.asbytes()), newly_pinned=True)
    supabase.table("devices").update({
        "ssh_host_key_type": pinned.key_type,
        "ssh_host_key": pinned.key_b64,
        "ssh_host_key_fingerprint": pinned.fingerprint,
        "ssh_host_key_pinned_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", device["id"]).execute()
    return pinned


def strict_connection_params(known_hosts_path: str) -> dict:
    """Netmiko kwargs that reject any host key not in known_hosts_path."""
    return {
        "ssh_strict": True,
        "system_host_keys": False,
        "alt_host_keys": True,
        "alt_key_file": known_hosts_path,
    }


def is_host_key_failure(exc: BaseException) -> bool:
    if isinstance(exc, (paramiko.BadHostKeyException, HostKeyError)):
        return True
    text = str(exc).lower()
    return "not found in known_hosts" in text or "host key" in text and ("mismatch" in text or "does not match" in text)


def describe_failure(exc: BaseException) -> Optional[str]:
    if isinstance(exc, HostKeyError):
        return str(exc)
    if is_host_key_failure(exc):
        return (
            "SSH host key does not match the pinned key. This can mean the device was replaced or "
            "re-keyed — or that someone is intercepting the connection. Verify the device, then reset "
            "the pinned key from the dashboard (admin only)."
        )
    return None
