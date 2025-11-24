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


def local_flows_detection(rows, config_dict):
    """
    Detect and handle flows where both src_ip and dst_ip are in LOCAL_NETWORKS,
    excluding any flows involving ROUTER_IPADDRESS.
    """
    logger = logging.getLogger(__name__)
    ROUTER_LIST = set(config_dict['RouterIpAddresses'].split(','))
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

    log_info(logger,"[INFO] Detecting flows for the same local networks going through the router")
    for row in rows:
        src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_, flow_start, flow_end, *_ = row

        # Skip if either IP is in ROUTER_IPADDRESS array
        is_router_ip = False
        for router_ip in ROUTER_LIST:
            if src_ip == router_ip or dst_ip == router_ip:
                is_router_ip = True

        if is_router_ip:
            continue

        # Determine if both IPs are in LOCAL_NETWORKS
        is_src_local = False
        is_dst_local = False
        if is_ip_in_range(src_ip, LOCAL_NETWORKS):
            is_src_local = True
        if is_ip_in_range(dst_ip, LOCAL_NETWORKS):
            is_dst_local = True

        if is_src_local and is_dst_local:
            log_info(logger, f"[INFO] Flow involves two local hosts: {src_ip} and {dst_ip}")
            message = f"Flow involves two local hosts: {src_ip} and {dst_ip}"

            handle_alert(
                config_dict,
                "LocalFlowsDetection",
                message,
                src_ip,
                row,
                "Flow involves two local hosts",
                dst_ip,
                dst_port,
                f"{src_ip}_{dst_ip}_{protocol}_{src_port}_{dst_port}_LocalFlowsDetection"
            )

    log_info(logger,"[INFO] Finished detecting flows for the same local network going through the router")