# agent/worker.py
#
# Long-running agent. Run it inside the network that can reach your devices;
# it only needs outbound HTTPS to Supabase, so the dashboard can stay on
# Vercel (or anywhere) without SSH reachability to the fleet.
#
#   python worker.py
#
# Loop:
#   1. every AEGIS_SCHEDULE_SECONDS, queue collect jobs for devices whose
#      per-device schedule (devices.collection_interval_minutes) is due
#   2. claim queued jobs (collect / remediate / rollback) from agent_jobs and
#      run up to AEGIS_WORKERS of them in parallel
import logging
import os
import signal
import socket
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable, Dict, Optional

import collector

log = logging.getLogger("worker")

WORKER_ID = os.getenv("AEGIS_WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}"
MAX_WORKERS = int(os.getenv("AEGIS_WORKERS", "5"))
POLL_SECONDS = float(os.getenv("AEGIS_POLL_SECONDS", "5"))
SCHEDULE_SECONDS = float(os.getenv("AEGIS_SCHEDULE_SECONDS", "60"))


def finish_job(supabase, job_id: str, status: str, result: Optional[dict] = None, error: Optional[str] = None) -> None:
    supabase.table("agent_jobs").update({
        "status": status,
        "result": result,
        "error": (error or "")[:2000] or None,
        "finished_at": collector.now_iso(),
    }).eq("id", job_id).execute()


def update_remediation(supabase, remediation_id: str, fields: dict) -> None:
    fields["updated_at"] = collector.now_iso()
    supabase.table("remediation_requests").update(fields).eq("id", remediation_id).execute()


def load_device(supabase, device_id: str) -> dict:
    res = supabase.table("devices").select("*").eq("id", device_id).limit(1).execute()
    if not res.data:
        raise collector.CollectionError(f"Device {device_id} no longer exists")
    return res.data[0]


def handle_collect(supabase, job: dict, device: dict) -> dict:
    return collector.collect_device(device, supabase)


def _apply_remediation(supabase, job: dict, device: dict, field: str, running: str, done: str) -> dict:
    remediation_id = (job.get("payload") or {}).get("remediation_id")
    if not remediation_id:
        raise collector.CollectionError("Job payload has no remediation_id")
    res = supabase.table("remediation_requests").select("*").eq("id", remediation_id).limit(1).execute()
    if not res.data:
        raise collector.CollectionError(f"Remediation {remediation_id} not found")
    request = res.data[0]
    commands = [line for line in (request.get(field) or "").splitlines() if line.strip()]
    if not commands:
        raise collector.CollectionError(f"Remediation {remediation_id} has no {field}")

    update_remediation(supabase, remediation_id, {"status": running})
    try:
        outcome = collector.apply_commands(device, supabase, commands)
    except Exception as e:
        update_remediation(supabase, remediation_id, {"status": "failed", "output": f"{type(e).__name__}: {e}"})
        collector.raise_alert(supabase, device, "remediation_result", "HIGH",
                              f"Change failed on {device.get('hostname')}: {request.get('title')}", str(e))
        raise

    update_remediation(supabase, remediation_id, {
        "status": done,
        "output": outcome["output"][-20000:],
        "pre_configuration_id": outcome["pre_configuration_id"],
        "post_configuration_id": outcome["post_configuration_id"],
    })
    return {"remediation_id": remediation_id, **{k: v for k, v in outcome.items() if k != "output"}}


def handle_remediate(supabase, job: dict, device: dict) -> dict:
    # "applied" -> the dashboard re-runs the CIS rules on the post-change
    # snapshot and moves it to verified / verification_failed.
    return _apply_remediation(supabase, job, device, "commands", "executing", "applied")


def handle_rollback(supabase, job: dict, device: dict) -> dict:
    return _apply_remediation(supabase, job, device, "rollback_commands", "rolling_back", "rolled_back")


HANDLERS: Dict[str, Callable] = {
    "collect": handle_collect,
    "remediate": handle_remediate,
    "rollback": handle_rollback,
}


def run_job(job: dict) -> None:
    supabase = collector.get_supabase_client()
    job_id = job["id"]
    log.info(f"Job {job_id}: {job['kind']} on device {job['device_id']}")
    device = None
    try:
        handler = HANDLERS.get(job["kind"])
        if not handler:
            raise collector.CollectionError(f"Unknown job kind {job['kind']}")
        device = load_device(supabase, job["device_id"])
        if device.get("is_mock"):
            raise collector.CollectionError("Mock devices are handled by the dashboard, not the SSH agent")
        result = handler(supabase, job, device)
        finish_job(supabase, job_id, "succeeded", result=result)
        log.info(f"Job {job_id} succeeded")
    except Exception as e:
        message = collector.mark_unreachable(supabase, device, e) if device and job["kind"] == "collect" else f"{type(e).__name__}: {e}"
        log.error(f"Job {job_id} failed: {message}")
        try:
            finish_job(supabase, job_id, "failed", error=message)
        except Exception as db_err:
            log.error(f"Could not record failure of job {job_id}: {db_err}")


def claim_job(supabase) -> Optional[dict]:
    res = supabase.rpc("claim_agent_job", {"p_worker": WORKER_ID}).execute()
    return res.data[0] if res.data else None


def main(stop: Optional[threading.Event] = None) -> None:
    stop = stop or threading.Event()
    supabase = collector.get_supabase_client()
    in_flight: Dict[str, Future] = {}
    last_schedule = 0.0
    log.info(f"Worker {WORKER_ID} started ({MAX_WORKERS} slots)")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        while not stop.is_set():
            for job_id in [j for j, f in in_flight.items() if f.done()]:
                in_flight.pop(job_id)

            if time.monotonic() - last_schedule >= SCHEDULE_SECONDS:
                last_schedule = time.monotonic()
                try:
                    queued = supabase.rpc("enqueue_due_collections", {}).execute().data
                    if queued:
                        log.info(f"Scheduled {queued} collection(s)")
                except Exception as e:
                    log.error(f"Scheduling failed: {e}")

            claimed_any = False
            while len(in_flight) < MAX_WORKERS and not stop.is_set():
                try:
                    job = claim_job(supabase)
                except Exception as e:
                    log.error(f"Claiming a job failed: {e}")
                    break
                if not job:
                    break
                claimed_any = True
                in_flight[job["id"]] = pool.submit(run_job, job)

            if not claimed_any:
                stop.wait(POLL_SECONDS)
    log.info("Worker stopped")


if __name__ == "__main__":
    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())
    main(stop_event)
