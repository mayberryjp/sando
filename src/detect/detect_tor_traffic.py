import logging

from src.database.configuration import get_local_network_cidrs
from src.database.tornodes import get_all_tor_nodes
from src.notifications.core import handle_alert
from src.utils.locallogging import log_error, log_info
from src.utils.network import is_ip_in_range


def detect_tor_traffic(rows, config_dict):
    """
    Detect traffic to/from known Tor nodes.

    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Started detecting traffic to tor nodes")

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
                message = (
                    f"Tor Traffic Detected:\n"
                    f"Local IP: {src_ip}\n"
                    f"Tor Node: {dst_ip}:{dst_port}\n"
                )

                log_info(
                    logger,
                    f"[INFO] Tor traffic detected: {src_ip} -> {dst_ip}:{dst_port}",
                )

                handle_alert(
                    config_dict,
                    "TorFlowDetection",
                    message,
                    src_ip,
                    row,
                    "Tor Traffic Detected",
                    dst_ip,
                    "Tor Exit Node",
                    alert_id,
                )

    except Exception as e:
        log_error(logger, f"[ERROR] Error in detect_tor_traffic: {e}")

    log_info(logger, "[INFO] Finished detecting traffic to tor nodes")
