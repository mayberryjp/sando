import logging

from src.database.configuration import get_local_network_cidrs
from src.notifications.core import handle_alert
from src.utils.locallogging import log_info
from src.utils.network import ip_to_int, is_ip_in_range


def detect_reputation_flows(rows, config_dict, reputation_data):
    """
    Detect flows where a local IP communicates with an IP on the reputation list.

    Args:
        rows: List of flow records.
        config_dict: Dictionary containing configuration settings.
        reputation_data: Preprocessed reputation list data.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Started detecting reputationlist destinations")
    # Pre-process reputation data into ranges
    reputation_ranges = []
    for entry in reputation_data:
        if len(entry) >= 4:  # Ensure entry has at least 4 elements
            network, start_ip, end_ip, netmask = entry[:4]
            reputation_ranges.append((network, start_ip, end_ip, netmask))

    # Sort ranges by start_ip for efficient lookup
    reputation_ranges.sort(key=lambda x: x[0])

    def find_match(ip_int):
        """Find if an IP is in the reputation list."""
        if not ip_int:
            return None

        for network, start_ip, end_ip, netmask in reputation_ranges:
            if start_ip <= ip_int <= end_ip:
                return (True, network)
            elif start_ip > ip_int:
                break  # Early exit if we've passed possible matches

        return (False, None)

    # Get local networks from the configuration
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

    # Process rows
    total = len(rows)
    matches = 0
    for index, row in enumerate(rows, 1):

        src_ip, dst_ip, src_port, dst_port, protocol, *_ = row

        # Convert IPs to integers
        src_ip_int = ip_to_int(src_ip)
        dst_ip_int = ip_to_int(dst_ip)

        if not src_ip_int or not dst_ip_int:
            continue

        # Check if src_ip or dst_ip is in LOCAL_NETWORKS
        is_src_local = is_ip_in_range(src_ip, LOCAL_NETWORKS)

        (reputation_match, match_network) = find_match(dst_ip_int)

        # If src_ip is local, check dst_ip against the reputation list
        if is_src_local and reputation_match:
            matches += 1
            log_info(
                logger,
                f"[INFO] Flow involves an IP on the reputation list: {src_ip} -> {dst_ip} ({match_network})",
            )

            message = (
                f"Flow involves an IP on the reputation list:\n"
                f"Source IP: {src_ip}\n"
                f"Destination IP: {dst_ip}\n"
                f"Match Network: {match_network}"
            )

            alert_id = f"{src_ip}_{dst_ip}_{protocol}_ReputationListDetection"

            handle_alert(
                config_dict,
                "ReputationListDetection",
                message,
                src_ip,
                row,
                "Flow involves an IP on the reputation list",
                dst_ip,
                match_network,
                alert_id,
            )

    log_info(
        logger,
        f"[INFO] Completed reputation flow processing. Found {matches} matches in {total} flows",
    )
