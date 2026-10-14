import base64

import paramiko
import pytest

import hostkeys
from fakes import FakeSupabase


@pytest.fixture
def key():
    return paramiko.RSAKey.generate(1024)


def test_pins_on_first_contact(key):
    device = {"id": "d1"}
    db = FakeSupabase(devices=[dict(device)])
    pinned = hostkeys.ensure_pinned(device, "10.0.0.1", 22, db, fetch=lambda h, p: key)
    assert pinned.newly_pinned
    row = db.tables["devices"][0]
    assert row["ssh_host_key"] == key.get_base64()
    assert row["ssh_host_key_type"] == "ssh-rsa"
    assert row["ssh_host_key_fingerprint"].startswith("SHA256:")


def test_uses_existing_pin_without_contacting_device(key):
    device = {"id": "d1", "ssh_host_key_type": "ssh-rsa", "ssh_host_key": key.get_base64()}

    def boom(*_):
        raise AssertionError("must not fetch when a key is pinned")

    pinned = hostkeys.ensure_pinned(device, "10.0.0.1", 22, FakeSupabase(), fetch=boom)
    assert not pinned.newly_pinned
    assert pinned.fingerprint == hostkeys.fingerprint_sha256(base64.b64decode(key.get_base64()))


def test_refuses_unpinned_when_required(key, monkeypatch):
    monkeypatch.setenv("AEGIS_REQUIRE_PINNED_HOST_KEYS", "true")
    with pytest.raises(hostkeys.HostKeyError):
        hostkeys.ensure_pinned({"id": "d1"}, "10.0.0.1", 22, FakeSupabase(), fetch=lambda h, p: key)


def test_known_hosts_uses_bracket_form_for_nonstandard_port():
    assert hostkeys.known_hosts_entry("10.0.0.1", 22, "ssh-ed25519", "AAA") == "10.0.0.1 ssh-ed25519 AAA\n"
    assert hostkeys.known_hosts_entry("10.0.0.1", 2222, "ssh-ed25519", "AAA") == "[10.0.0.1]:2222 ssh-ed25519 AAA\n"


def test_paramiko_rejects_a_different_key(key, tmp_path):
    """The known_hosts file we write must make paramiko refuse any other key."""
    pinned = hostkeys.PinnedKey("ssh-rsa", key.get_base64(), "")
    path = hostkeys.write_known_hosts("10.0.0.1", 22, pinned)
    client = paramiko.SSHClient()
    client.load_host_keys(path)
    other = paramiko.RSAKey.generate(1024)
    assert client.get_host_keys().check("10.0.0.1", key)
    assert not client.get_host_keys().check("10.0.0.1", other)


def test_strict_params_reject_unknown_hosts():
    params = hostkeys.strict_connection_params("/tmp/kh")
    assert params["ssh_strict"] is True
    assert params["system_host_keys"] is False


def test_describes_mismatch(key):
    exc = paramiko.BadHostKeyException("10.0.0.1", paramiko.RSAKey.generate(1024), key)
    assert "does not match the pinned key" in hostkeys.describe_failure(exc)
    assert hostkeys.describe_failure(TimeoutError("timed out")) is None
