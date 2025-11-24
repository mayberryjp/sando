
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

def detect_many_destinations(rows, config_dict):
    """
    Detect hosts from local networks that are communicating with an unusually high
    number of different destination IPs, which could indicate scanning or malware.

    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Started one source to many destinations detection")

    # Get configuration parameters
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)
    dest_threshold = int(config_dict.get("MaxUniqueDestinations", "30"))

    # Track destinations per source IP
    source_stats = {}

    # First pass: Count unique destinations for each source IP
    for row in rows:
        src_ip, dst_ip, *_ = row

        # Only check sources from local networks
        if not is_ip_in_range(src_ip, LOCAL_NETWORKS):
            continue

        # Initialize source IP tracking if not already present
        if src_ip not in source_stats:
            source_stats[src_ip] = {
                'destinations': set(),
                'ports': set(),
                'flow': row
            }

        # Track unique destinations
        source_stats[src_ip]['destinations'].add(dst_ip)

    # Second pass: Check for threshold violations and alert
    for src_ip, stats in source_stats.items():
        unique_dests = len(stats['destinations'])
        flow = stats['flow']

        # Check if the threshold is exceeded
        if unique_dests > dest_threshold:
            alert_id = f"{src_ip}_ManyDestinations"

            message = (f"Host Connecting to Many Destinations:\n"
                       f"Source IP: {src_ip}\n"
                       f"Unique Destinations: {unique_dests}\n")

            log_info(logger, f"[INFO] Excessive destinations detected from {src_ip}: {unique_dests} destinations")

            handle_alert(
                config_dict,
                "ManyDestinationsDetection",
                message,
                src_ip,
                flow,
                "Excessive Unique Destinations",
                "",
                f"{unique_dests} destinations",
                alert_id
            )

    log_info(logger, "[INFO] Finished one source to many destinations detection")

