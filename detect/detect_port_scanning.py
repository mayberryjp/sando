
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

def detect_port_scanning(rows, config_dict):
    """
    Detect local hosts that are connecting to many different ports on the same destination IP,
    which could indicate port scanning activity. Only considers TCP flows (protocol 6).

    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Started detecting port scanning activity")

    # Get configuration parameters
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)
    port_threshold = int(config_dict.get("MaxPortsPerDestination", "15"))

    # Dictionary to track {(src_ip, dst_ip): {ports}}
    scan_tracking = {}

    # First pass: Iterate through all rows to collect data
    for row in rows:
        src_ip, dst_ip, src_port, dst_port, protocol, *_ = row

        # Only process TCP flows (protocol 6)
        if protocol != 6:
            continue

        # Only check flows where src_port > dst_port
        if src_port <= dst_port:
            continue

        # Only check sources from local networks
        if not is_ip_in_range(src_ip, LOCAL_NETWORKS):
            continue

        # Create key for tracking
        flow_key = (src_ip, dst_ip)

        # Initialize tracking for new source-destination pair
        if flow_key not in scan_tracking:
            scan_tracking[flow_key] = {
                'ports': set(),
                'flow': row
            }

        # Track unique destination ports
        scan_tracking[flow_key]['ports'].add(dst_port)

    # Second pass: Iterate through all tracked source-destination pairs
    for (src_ip, dst_ip), stats in scan_tracking.items():
        unique_ports = len(stats['ports'])

        # Check if the port threshold is exceeded
        if unique_ports > port_threshold:
            alert_id = f"{src_ip}_{dst_ip}_PortScan"

            message = (f"Potential Port Scan Detected:\n"
                       f"Source IP: {src_ip}\n"
                       f"Target IP: {dst_ip}\n"
                       f"Unique Ports: {unique_ports}\n")

            log_info(logger, f"[INFO] Port scan detected from {src_ip} to {dst_ip}: {unique_ports} ports")

            handle_alert(
                config_dict,
                "PortScanDetection",
                message,
                src_ip,
                row,
                "Port Scan Detected",
                dst_ip,
                f"Ports:{unique_ports}",
                alert_id
            )

    log_info(logger, "[INFO] Finished detecting port scanning activity")