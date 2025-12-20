import logging

from src.database.configuration import get_local_network_cidrs
from src.notifications.core import handle_alert
from src.utils.locallogging import log_info
from src.utils.network import is_ip_in_range


def detect_high_bandwidth_flows(rows, config_dict):
    """
    Detect flows where the total packet or byte rates for a single src_ip or dst_ip exceed thresholds.

    Args:
        rows: List of flow records.
        config_dict: Dictionary containing configuration settings.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Started detecting high bandwidth flows")

    # Get thresholds from config_dict
    packet_rate_threshold = int(
        config_dict.get("MaxPackets", "30000")
    )  # Default: 1000 packets/sec
    byte_rate_threshold = int(
        config_dict.get("MaxBytes", "30000000")
    )  # Default: 1 MB/sec

    # Dictionary to track totals for each src_ip and dst_ip
    traffic_stats = {}
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

    # First pass: Aggregate traffic by src_ip and dst_ip
    for row in rows:
        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            packets,
            bytes_,
            flow_start,
            flow_end,
            *_,
        ) = row

        # Initialize stats for src_ip
        if src_ip not in traffic_stats:
            traffic_stats[src_ip] = {"packets": 0, "bytes": 0, "flows": []}
        traffic_stats[src_ip]["packets"] += packets
        traffic_stats[src_ip]["bytes"] += bytes_
        traffic_stats[src_ip]["flows"].append(row)

        # Initialize stats for dst_ip
        if dst_ip not in traffic_stats:
            traffic_stats[dst_ip] = {"packets": 0, "bytes": 0, "flows": []}
        traffic_stats[dst_ip]["packets"] += packets
        traffic_stats[dst_ip]["bytes"] += bytes_
        traffic_stats[dst_ip]["flows"].append(row)

    # Second pass: Check for threshold violations
    for ip, stats in traffic_stats.items():

        if not is_ip_in_range(ip, LOCAL_NETWORKS):
            continue

        total_packets = stats["packets"]
        total_bytes = stats["bytes"]

        # Check if the thresholds are exceeded
        if total_packets > packet_rate_threshold or total_bytes > byte_rate_threshold:
            alert_id = f"{ip}_HighBandwidthFlow"

            message = (
                f"High Bandwidth Flow Detected:\n"
                f"IP Address: {ip}\n"
                f"Total Packets: {total_packets}\n"
                f"Total Bytes: {total_bytes}\n"
            )

            log_info(
                logger,
                f"[INFO] High bandwidth flow detected for {ip}: "
                f"Packets: {total_packets}, Bytes: {total_bytes}",
            )

            handle_alert(
                config_dict,
                "HighBandwidthFlowDetection",
                message,
                ip,
                stats["flows"][0],  # Use the first row for this IP
                "High Bandwidth Flow Detected",
                "Aggregate",
                f"Packets: {total_packets}, Bytes: {total_bytes}",
                alert_id,
            )

    log_info(logger, "[INFO] Finished detecting high bandwidth flows")
