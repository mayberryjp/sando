import sys
import requests
import subprocess
import sys
import time
import os
from pathlib import Path
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
sys.path.insert(0, "/database")
import psutil
import time
from datetime import datetime
import logging
from src.detached import insert_action_detached
from init import *


# List of required Python script names
required_scripts = ["processor.py", "discovery.py", "api.py", "collector.py","fetch.py","sinkholedns.py"]

def is_script_running(script_name):
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline')
            if cmdline and isinstance(cmdline, list):
                cmdline_str = " ".join(cmdline)
                if script_name in cmdline_str:
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

def check_scripts():
    logger = logging.getLogger(__name__)
    missing = [script for script in required_scripts if not is_script_running(script)]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if missing:
        insert_action_detached(f"[ERROR] Missing python processes: {', '.join(missing)}. Please restart container and check configuration, errors. ")
        log_error(logger,f"[ERROR] Missing python processes: {', '.join(missing)}. Please restart container and check configuration, errors. ")
    else:
        log_info(logger,"[INFO] All required python processes are running")

def check_api_health_and_restart():
    """
    Checks /api/online/consolidated and /api/online/explore endpoints.
    If either returns a connection error or {"online": false}, restarts api.py.
    """
    logger = logging.getLogger(__name__)
    endpoints = [
        "http://localhost:8044/api/online/consolidated",
        "http://localhost:8044/api/online/explore"
    ]
    unhealthy = False

    for url in endpoints:
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code != 200:
                log_error(logger, f"[ERROR] Health check failed for {url}: HTTP {resp.status_code}")
                unhealthy = True
            else:
                data = resp.json()
                if not data.get("online", False):
                    log_error(logger, f"[ERROR] Health check failed for {url}: online is False")
                    unhealthy = True
        except Exception as e:
            log_error(logger, f"[ERROR] Exception during health check for {url}: {e}")
            unhealthy = True

    if unhealthy:
        log_info(logger, "[INFO] Attempting to terminate api.py process due to failed health check...")
        try:
            insert_action(f"Health check failed for API endpoints. There may be a problem with API health.")
            # Find and terminate the running api.py process
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info.get('cmdline')
                    if cmdline and any("api.py" in part for part in cmdline):
                        log_info(logger, f"[INFO] Terminating api.py process with PID {proc.pid}")
                        proc.terminate()
                        proc.wait(timeout=10)
                except Exception:
                    continue
            log_info(logger, "[INFO] api.py process terminated due to health check failure.")
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to terminate api.py: {e}")


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    time.sleep(180)
    log_info(logger,"[INFO] Starting health monitor... (checks every 60 seconds)")
    while True:
        check_scripts()
        check_api_health_and_restart()
        time.sleep(60)
