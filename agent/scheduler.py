# agent/scheduler.py
# Kept so existing "python scheduler.py" setups keep working. Scheduling now
# lives in worker.py: per-device intervals (devices.collection_interval_minutes)
# plus on-demand jobs queued from the dashboard.
import signal
import threading

import worker

if __name__ == "__main__":
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    worker.main(stop)
