# agent/scheduler.py
import sys           #  was used below (sys.executable) but never imported -> crashed on first run
import subprocess
import schedule
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("scheduler")


def run_collector():
    log.info("Running telemetry collector...")
    try:
        subprocess.run([sys.executable, "collector.py"], check=True)
    except subprocess.CalledProcessError as e:
        log.error("Collector failed with exit code: %s", e.returncode)
    except FileNotFoundError:
        # FIX: collector.py not found gave an unhandled traceback before
        log.error("collector.py not found in current working directory.")


schedule.every(1).hours.do(run_collector)

log.info("Telemetry scheduler active. Waiting for schedule... (Press Ctrl+C to stop)")

try:
    while True:
        schedule.run_pending()
        time.sleep(60)
except KeyboardInterrupt:
    #  clean shutdown instead of a raw traceback on Ctrl+C
    log.info("Scheduler stopped by user.")
    sys.exit(0)
