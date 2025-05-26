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

def detect_new_outbound_connections(rows, config_dict):
    """
    Detect new outbound connections from local clients to external servers.
    A server is identified by having a lower port number than the client.
    
    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger,f"[INFO] Preparing to detect new outbound connections")

    LOCAL_NETWORKS = set(config_dict['LocalNetworks'].split(','))

    try:

        for row in rows:
            src_ip, dst_ip, src_port, dst_port, protocol = row[0:5]
            
            # Check if source IP is in any of the local networks
            is_src_local = False

            if is_ip_in_range(src_ip, LOCAL_NETWORKS):
                is_src_local = True
            
            # If source is local and destination port is lower (indicating server),
            # this might be a new outbound connection
            if is_src_local and dst_port < src_port:
                # Create a unique identifier for this connection
                alert_id = f"{src_ip}_{dst_ip}_{protocol}_{dst_port}_NewOutboundDetection"
                
                message = (f"New outbound connection detected:\n"
                            f"Local client: {src_ip}\n"
                            f"Remote server: {dst_ip}:{dst_port}\n"
                            f"Protocol: {protocol}")
                
                log_info(logger, f"[INFO] New outbound connection detected: {src_ip} -> {dst_ip}:{dst_port}")

                handle_alert(
                    config_dict,
                    "NewOutboundDetection",
                    message,
                    src_ip,
                    row,
                    "New outbound connection detected",
                    dst_ip,
                    dst_port,
                    alert_id
                )    

    except Exception as e:
        log_error(logger, f"[ERROR] Error in detect_new_outbound_connections: {e}")
    
    log_info(logger,f"[INFO] Finished detecting new outbound connections")
