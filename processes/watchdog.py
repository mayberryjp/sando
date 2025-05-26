import sys
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

if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    log_info(logger,"[INFO] Starting health monitor... (checks every 60 seconds)")
    while True:
        check_scripts()
        time.sleep(60)
