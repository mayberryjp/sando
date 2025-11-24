

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


def detect_tor_traffic(rows, config_dict):
    """
    Detect traffic to/from known Tor nodes.
    
    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger,"[INFO] Started detecting traffic to tor nodes")

    # Get local networks
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)
    
    try:
        tor_rows = get_all_tor_nodes()

        tor_nodes = set(row[0] for row in tor_rows)
        
        for row in rows:
            src_ip, dst_ip, src_port, dst_port, protocol, *_ = row
            
            # Check if source is local and destination is Tor node
            is_src_local = is_ip_in_range(src_ip, LOCAL_NETWORKS)
            
            if is_src_local and dst_ip in tor_nodes:
                alert_id = f"{src_ip}_{dst_ip}_{protocol}_{dst_port}_TorTraffic"
                message = (f"Tor Traffic Detected:\n"
                          f"Local IP: {src_ip}\n"
                          f"Tor Node: {dst_ip}:{dst_port}\n")
                
                log_info(logger, f"[INFO] Tor traffic detected: {src_ip} -> {dst_ip}:{dst_port}")

                handle_alert(
                    config_dict,
                    "TorFlowDetection",
                    message,
                    src_ip,
                    row,
                    "Tor Traffic Detected",
                    dst_ip,
                    f"Tor Exit Node",
                    alert_id
                )
                    
    except Exception as e:
        log_error(logger, f"[ERROR] Error in detect_tor_traffic: {e}")

    log_info(logger,"[INFO] Finished detecting traffic to tor nodes")