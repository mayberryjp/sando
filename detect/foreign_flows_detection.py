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


def foreign_flows_detection(rows, config_dict):
    """
    Detect and handle flows where neither src_ip nor dst_ip is in LOCAL_NETWORKS.
    """
    logger = logging.getLogger(__name__)
    log_info(logger,"[INFO] Detecting flows that don't involve any local network")
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

    for row in rows:
        src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_, flow_start, flow_end, *_ = row

        # Determine if neither src_ip nor dst_ip is in LOCAL_NETWORKS
        is_src_local = False
        is_dst_local = False
        

        if is_ip_in_range(src_ip, LOCAL_NETWORKS):
            is_src_local = True
        if is_ip_in_range(dst_ip, LOCAL_NETWORKS):
            is_dst_local = True


        if not is_src_local and not is_dst_local:
            log_info(logger, f"[INFO] Flow involves two foreign hosts: {src_ip} and {dst_ip}")

            message = f"Flow involves two foreign hosts: {src_ip} and {dst_ip}"

            handle_alert(
                config_dict,
                "ForeignFlowsDetection",
                message,
                src_ip,
                row,
                "Flow involves two foreign hosts",
                dst_ip,
                dst_port,
                f"{src_ip}_{dst_ip}_{protocol}_{src_port}_{dst_port}_ForeignFlowsDetection"
            )
            
    log_info(logger,"[INFO] Finished detecting flows that don't involve any local network")