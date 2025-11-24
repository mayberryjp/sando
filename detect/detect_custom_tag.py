
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

def detect_custom_tag(rows, config_dict):
    """
    Detect and alert on rows with tags matching the AlertOnCustomTag configuration.

    Args:
        rows: List of flow records.
        config_dict: Dictionary containing configuration settings.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Started detecting custom tag alerts")

    # Get the list of tags to alert on
    alert_tags = set(tag.strip() for tag in config_dict.get("AlertOnCustomTagList", "").split(",") if tag.strip())

    if not alert_tags:
        log_warn(logger, "[WARN] No tags specified in AlertOnCustomTag.")
        return

    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

    log_info(logger, f"[INFO] Alerting on the following tags: {alert_tags}")

    # Iterate through rows to check for matching tags
    for row in rows:
        src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, flow_start, flow_end, times_seen, last_seen, tags = row
        # Ensure the row has a 'tags' column

        if not is_ip_in_range(src_ip, LOCAL_NETWORKS):
            continue

        # Check if any tag in the row matches the alert tags
        row_tags = set(tags.split(";")) if tags else set()
        matching_tags = row_tags.intersection(alert_tags)

        if matching_tags:
            # Generate an alert for the matching tags

            alert_id = f"{src_ip}_{dst_ip}_{protocol}_{dst_port}_CustomTagAlert_{matching_tags}"

            message = (f"Custom Tag Alert Detected:\n"
                       f"Source IP: {src_ip}\n"
                       f"Destination IP: {dst_ip}:{dst_port}\n"
                       f"Protocol: {protocol}\n"
                       f"Matching Tags: {', '.join(matching_tags)}")

            log_info(logger, f"[INFO] Custom tag alert detected: {src_ip} -> {dst_ip}:{dst_port} Tags: {', '.join(matching_tags)} ")

            # Call the reusable function
            handle_alert(
                config_dict,
                "CustomTagAlertDetection",
                message,
                src_ip,
                row,
                "Custom Tag Alert Detected",
                dst_ip,
                f"Tags: {', '.join(matching_tags)}",
                alert_id
            )

    log_info(logger, "[INFO] Finished detecting custom tag alerts")