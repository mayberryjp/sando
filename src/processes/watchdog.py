import logging
import time

import psutil
import requests

from src.database.actions import insert_action
from src.detached import insert_action_detached
from src.utils.locallogging import log_error, log_info

# List of required Python process module names
required_processes = [
    "processor",
    "discovery",
    "api",
    "collector",
    "fetch",
    "sinkholedns",
    "dhcpserver",
]


# Check for process running as 'python -m src.processes.<name>'
def is_process_running(process_name):
    target = f"python -m src.processes.{process_name}"
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = proc.info.get("cmdline")
            if cmdline and isinstance(cmdline, list):
                cmdline_str = " ".join(cmdline)
                if target in cmdline_str:
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False


def check_processes():
    logger = logging.getLogger(__name__)
    missing = [proc for proc in required_processes if not is_process_running(proc)]
    if missing:
        insert_action_detached(
            f"[ERROR] Missing python processes: {', '.join(missing)}. Please restart container and check configuration, errors. "
        )
        log_error(
            logger,
            f"[ERROR] Missing python processes: {', '.join(missing)}. Please restart container and check configuration, errors. ",
        )
    else:
        log_info(logger, "[INFO] All required python processes are running")


def check_api_health_and_restart():
    """
    Checks /api/online/consolidated and /api/online/explore endpoints.
    If either returns a connection error or {"online": false}, restarts api.py.
    """
    logger = logging.getLogger(__name__)
    endpoints = [
        "http://localhost:8044/api/online/consolidated",
        "http://localhost:8044/api/online/explore",
    ]
    unhealthy = False

    for url in endpoints:
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code != 200:
                log_error(
                    logger,
                    f"[ERROR] Health check failed for {url}: HTTP {resp.status_code}",
                )
                unhealthy = True
            else:
                data = resp.json()
                if not data.get("online", False):
                    log_error(
                        logger,
                        f"[ERROR] Health check failed for {url}: online is False",
                    )
                    unhealthy = True
        except Exception as e:
            log_error(logger, f"[ERROR] Exception during health check for {url}: {e}")
            unhealthy = True

    if unhealthy:
        log_info(
            logger,
            "[INFO] Attempting to terminate api process due to failed health check...",
        )
        try:
            insert_action(
                "Health check failed for API endpoints. There may be a problem with API health."
            )
            # Find and terminate the running 'python -m src.processes.api' process
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    cmdline = proc.info.get("cmdline")
                    if cmdline and "python -m src.processes.api" in " ".join(cmdline):
                        log_info(
                            logger,
                            f"[INFO] Terminating api process with PID {proc.pid}",
                        )
                        proc.terminate()
                        proc.wait(timeout=10)
                except Exception:
                    continue
            log_info(
                logger, "[INFO] api process terminated due to health check failure."
            )
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to terminate api process: {e}")


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    SLEEP_INITIAL = 180
    log_info(logger, f"[INFO] Watchdog process started. Waiting {SLEEP_INITIAL} before doing anything. Initializing...")
    time.sleep(SLEEP_INITIAL)
    log_info(logger, "[INFO] Running process monitor... (checks every 60 seconds)")
    while True:
        check_processes()
        check_api_health_and_restart()
        time.sleep(60)
