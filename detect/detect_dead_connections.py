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
from database.ignorelist import get_ignorelist

def detect_dead_connections(config_dict):
    """
    Detect dead connections by finding flows with:
    - Multiple sent packets but no received packets
    - Seen multiple times
    - Not ICMP or IGMP protocols
    - Not multicast or broadcast destinations
    
    Args:
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger, f"[INFO] Started detecting unresponsive destinations")

    # Get local networks from the configuration
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)
    dead_connections = get_dead_connections_from_database()
    ignorelist_entries = get_ignorelist()
    log_info(logger, f"[INFO] Found {len(dead_connections)} potential dead connections")

    for row in dead_connections:
        
        src_ip = row[0]
        dst_ip = row[1]
        dst_port = row[2]
        src_port = row[3]
        protocol = row[5]
        row_tags = row[6]  # Existing tags for the flow

        # Skip if src_ip is not in LOCAL_NETWORKS
        if not is_ip_in_range(src_ip, LOCAL_NETWORKS):
            continue

        alert_id = f"{src_ip}_{dst_ip}_{protocol}_{dst_port}_DeadConnection"
        
        message = (f"Dead Connection Detected:\n"
                    f"Source: {src_ip}\n"
                    f"Destination: {dst_ip}:{dst_port}\n"
                    f"Protocol: {protocol}\n")
        
        log_info(logger, f"[INFO] Dead connection detected: {src_ip}->{dst_ip}:{dst_port} {protocol}")
        
        # Add a Tag to the matching row using update_tag
        if not update_tag_to_allflows("allflows", "DeadConnectionDetection;", src_ip, dst_ip, dst_port):
            log_error(logger, f"[ERROR] Failed to add tag for flow: {src_ip} -> {dst_ip}:{dst_port}")


        handle_alert(
            config_dict,
            "DeadConnectionDetection",
            message,
            src_ip,
            row,
            "Dead Connection Detected",
            dst_ip,
            dst_port,
            alert_id
        )

    log_info(logger, f"[INFO] Finished detecting unresponsive destinations")