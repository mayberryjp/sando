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


def router_flows_detection(rows, config_dict):
    """
    Detect and handle flows involving a router IP address.
    Uses exact IP matching instead of network matching.
    """
    logger = logging.getLogger(__name__)
    log_info(logger,"[INFO] Detecting flows to or from the router")

    ROUTER_LIST = get_routers(config_dict)
    for row in rows:
        src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_, flow_start, flow_end, *_ = row

        # Determine if the flow involves a router IP address using exact matching
        router_ip_seen = None
        router_port = None
        for router_ip in ROUTER_LIST:
            if src_ip == router_ip:
                router_ip_seen = src_ip
                router_port = src_port
            elif dst_ip == router_ip:
                router_ip_seen = dst_ip
                router_port = dst_port

        if router_ip_seen:
            original_flow = json.dumps(row)
            log_info(logger, f"[INFO] Flow involves a router IP address: {router_ip_seen}")

            message = f"Flow involves a router IP address: {router_ip_seen}"

            handle_alert(
                config_dict,
                "RouterFlowsDetection",
                message,
                router_ip_seen,
                row,
                "Flow involves a router IP address",
                src_port,
                dst_port,
                f"{router_ip_seen}_{src_ip}_{dst_ip}_{protocol}_{router_port}_RouterFlowsDetection"
            )

    log_info(logger,"[INFO] Finished detecting flows to or from the router")