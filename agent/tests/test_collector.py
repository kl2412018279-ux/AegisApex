import pytest

import collector
from fakes import FakeSupabase


@pytest.mark.parametrize("text,expected", [
    ("Cisco IOS XE Software, Version 17.09.05", "17.09.05"),
    ("Junos: 21.4R3-S5.4", "21.4R3-S5.4"),
    ("sw-version: 10.2.4-h4", "10.2.4-h4"),
    ("Version: FortiGate-100F v7.2.5,build1517,230606 (GA.F)", "7.2.5"),
    ("version: 7.11.2 (stable)", "7.11.2"),
    ("", ""),
])
def test_extract_clean_os_version(text, expected):
    assert collector.extract_clean_os_version(text) == expected


def test_unreachable_alert_only_on_transition():
    db = FakeSupabase(devices=[{"id": "d1", "hostname": "R1", "connection_status": "online"}])
    device = dict(db.tables["devices"][0])
    collector.mark_unreachable(db, device, TimeoutError("timed out"))
    assert db.tables["devices"][0]["connection_status"] == "unreachable"
    assert [a["kind"] for a in db.tables["alert_events"]] == ["device_unreachable"]

    device = dict(db.tables["devices"][0])  # now already unreachable
    collector.mark_unreachable(db, device, TimeoutError("timed out"))
    assert len(db.tables["alert_events"]) == 1


def test_host_key_mismatch_is_critical_every_time():
    import paramiko
    db = FakeSupabase(devices=[{"id": "d1", "hostname": "R1", "connection_status": "unreachable"}])
    k1, k2 = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    collector.mark_unreachable(db, dict(db.tables["devices"][0]), paramiko.BadHostKeyException("h", k1, k2))
    alert = db.tables["alert_events"][0]
    assert alert["kind"] == "host_key_mismatch"
    assert alert["severity"] == "CRITICAL"


def test_store_snapshot_marks_source_and_scan():
    db = FakeSupabase(devices=[{"id": "d1"}])
    cid = collector.store_snapshot(db, {"id": "d1"}, "hostname R1\n" * 3, "Version 17.9.5")
    assert db.tables["configurations"][0]["source"] == "ssh"
    assert db.tables["scans"][0]["configuration_id"] == cid
    assert db.tables["devices"][0]["os_version"] == "17.9.5"


def test_pre_change_snapshot_is_not_current():
    db = FakeSupabase(devices=[{"id": "d1", "last_config": "old"}])
    collector.store_snapshot(db, {"id": "d1"}, "pre-change config text", "", current=False)
    assert db.tables["devices"][0]["last_config"] == "old"
    assert "scans" not in db.tables


def test_open_session_requires_username(monkeypatch):
    db = FakeSupabase()
    monkeypatch.setattr(collector, "fetch_decrypted_credentials", lambda *_: {"ssh_pass": "x"})
    with pytest.raises(collector.CollectionError, match="Refusing to guess"):
        with collector.open_session({"id": "d1", "ip_address": "10.0.0.1"}, db):
            pass
