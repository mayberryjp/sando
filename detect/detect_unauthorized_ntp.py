import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
import time
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
from locallogging import log_info, log_error, log_warn
from notifications.core import handle_alert
from init import *

def detect_unauthorized_ntp(rows, config_dict):
    """
    Detect DNS traffic (port 53) that doesn't involve approved DNS servers,
    but only alert if the src_ip is in local networks.

    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """

    logger = logging.getLogger(__name__)
    log_info(logger,"[INFO] Detecting unauthorized NTP destinations")
    # Get the list of approved NTP servers
    approved_ntp_servers = set(config_dict.get("ApprovedLocalNtpServersList", "").split(","))

    try:
        scopes_raw = config_dict.get("LocalNetworks", "[]")
        scopes = json.loads(scopes_raw)
        for scope in scopes:
            ntp_list = scope.get("ntp_servers", [])
            approved_ntp_servers.update(ntp_list)
    except Exception as e:
        log_warn(logger, f"[WARN] Could not parse scope NTP servers: {e}")

    if not approved_ntp_servers:
        log_warn(logger, "[WARN] No approved NTP servers configured")
        return

    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

    filtered_rows = [row for row in rows if row[3] == 123]

    for row in filtered_rows:
        src_ip, dst_ip, src_port, dst_port, protocol = row[0:5]

        # Check if either IP is not in the approved NTP servers list
        if src_ip not in approved_ntp_servers:
            if is_ip_in_range(src_ip, LOCAL_NETWORKS):
            # Create a unique identifier for this alert
                alert_id = f"{src_ip}_{dst_ip}__UnauthorizedNTP"

                log_info(logger, f"[INFO] Unauthorized NTP Traffic Detected: {src_ip} -> {dst_ip}")

                message = (f"Unauthorized NTP Traffic Detected:\n"
                        f"Source: {src_ip}:{src_port}\n"
                        f"Destination: {dst_ip}:{dst_port}\n"
                        f"Protocol: {protocol}")

                handle_alert(
                    config_dict,
                    "BypassLocalNtpDetection",
                    message,
                    src_ip,
                    row,
                    "Unauthorized NTP Traffic Detected",
                    dst_ip,
                    dst_port,
                    alert_id
                )

    log_info(logger,"[INFO] Finished detecting unauthorized NTP destinations")