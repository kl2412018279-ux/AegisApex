import collector
import worker
from fakes import FakeSupabase


def _setup(monkeypatch, db):
    monkeypatch.setattr(collector, "get_supabase_client", lambda: db)


def test_collect_job_success(monkeypatch):
    db = FakeSupabase(devices=[{"id": "d1", "hostname": "R1"}], agent_jobs=[{"id": "j1", "kind": "collect", "device_id": "d1"}])
    _setup(monkeypatch, db)
    monkeypatch.setattr(collector, "collect_device", lambda device, sb: {"configuration_id": "c1"})
    worker.run_job(db.tables["agent_jobs"][0])
    job = db.tables["agent_jobs"][0]
    assert job["status"] == "succeeded"
    assert job["result"] == {"configuration_id": "c1"}


def test_collect_job_failure_marks_device(monkeypatch):
    db = FakeSupabase(devices=[{"id": "d1", "hostname": "R1", "connection_status": "online"}],
                      agent_jobs=[{"id": "j1", "kind": "collect", "device_id": "d1"}])
    _setup(monkeypatch, db)

    def fail(*_):
        raise TimeoutError("timed out")

    monkeypatch.setattr(collector, "collect_device", fail)
    worker.run_job(db.tables["agent_jobs"][0])
    assert db.tables["agent_jobs"][0]["status"] == "failed"
    assert "timed out" in db.tables["agent_jobs"][0]["error"]
    assert db.tables["devices"][0]["connection_status"] == "unreachable"


def test_mock_devices_are_refused(monkeypatch):
    db = FakeSupabase(devices=[{"id": "d1", "is_mock": True}], agent_jobs=[{"id": "j1", "kind": "collect", "device_id": "d1"}])
    _setup(monkeypatch, db)
    worker.run_job(db.tables["agent_jobs"][0])
    assert db.tables["agent_jobs"][0]["status"] == "failed"


def test_remediation_job_records_outcome(monkeypatch):
    db = FakeSupabase(
        devices=[{"id": "d1", "hostname": "R1"}],
        remediation_requests=[{"id": "r1", "title": "Disable HTTP", "commands": "no ip http server\n", "status": "approved"}],
        agent_jobs=[{"id": "j1", "kind": "remediate", "device_id": "d1", "payload": {"remediation_id": "r1"}}],
    )
    _setup(monkeypatch, db)
    sent = {}

    def fake_apply(device, sb, commands, save=True):
        sent["commands"] = commands
        return {"output": "ok", "pre_configuration_id": "pre", "post_configuration_id": "post"}

    monkeypatch.setattr(collector, "apply_commands", fake_apply)
    worker.run_job(db.tables["agent_jobs"][0])
    req = db.tables["remediation_requests"][0]
    assert sent["commands"] == ["no ip http server"]
    assert req["status"] == "applied"
    assert req["post_configuration_id"] == "post"
    assert db.tables["agent_jobs"][0]["status"] == "succeeded"


def test_failed_remediation_alerts(monkeypatch):
    db = FakeSupabase(
        devices=[{"id": "d1", "hostname": "R1"}],
        remediation_requests=[{"id": "r1", "title": "x", "commands": "bad cmd", "status": "approved"}],
        agent_jobs=[{"id": "j1", "kind": "remediate", "device_id": "d1", "payload": {"remediation_id": "r1"}}],
    )
    _setup(monkeypatch, db)

    def fail(*_, **__):
        raise RuntimeError("% Invalid input")

    monkeypatch.setattr(collector, "apply_commands", fail)
    worker.run_job(db.tables["agent_jobs"][0])
    assert db.tables["remediation_requests"][0]["status"] == "failed"
    assert db.tables["alert_events"][0]["kind"] == "remediation_result"
    # a failed change must not mark the device unreachable
    assert "connection_status" not in db.tables["devices"][0]
