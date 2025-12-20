import json
import logging

from src.database.configuration import get_local_network_cidrs
from src.notifications.core import handle_alert
from src.utils.locallogging import log_info, log_warn
from src.utils.network import is_ip_in_range


def detect_unauthorized_dns(rows, config_dict):
    """
    Detect DNS traffic (port 53) that doesn't involve approved DNS servers,
    but only alert if the src_ip is in local networks.

    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting detecting unauthorized DNS destinations")
    # Get the list of approved DNS servers
    approved_dns_servers = set(
        config_dict.get("ApprovedLocalDnsServersList", "").split(",")
    )

    try:
        scopes_raw = config_dict.get("LocalNetworks", "[]")
        scopes = json.loads(scopes_raw)
        for scope in scopes:
            dns_list = scope.get("dns_servers", [])
            approved_dns_servers.update(dns_list)
    except Exception as e:
        log_warn(logger, f"[WARN] Could not parse scope DNS servers: {e}")

    if not approved_dns_servers:
        log_warn(logger, "[WARN] No approved DNS servers configured")
        return

    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)
    filtered_rows = [row for row in rows if row[3] == 53]

    for row in filtered_rows:
        src_ip, dst_ip, src_port, dst_port, protocol = row[0:5]

        # Check if either IP is not in the approved DNS servers list
        if dst_ip not in approved_dns_servers:
            if is_ip_in_range(src_ip, LOCAL_NETWORKS):
                # Create a unique identifier for this alert
                alert_id = f"{src_ip}_{dst_ip}__UnauthorizedDNS"

                log_info(
                    logger,
                    f"[INFO] Unauthorized DNS Traffic Detected: {src_ip} -> {dst_ip}",
                )

                message = (
                    f"Unauthorized DNS Traffic Detected:\n"
                    f"Source: {src_ip}:{src_port}\n"
                    f"Destination: {dst_ip}:{dst_port}\n"
                    f"Protocol: {protocol}"
                )

                handle_alert(
                    config_dict,
                    "BypassLocalDnsDetection",
                    message,
                    src_ip,
                    row,
                    "Unauthorized DNS Traffic Detected",
                    dst_ip,
                    dst_port,
                    alert_id,
                )

    log_info(logger, "[INFO] Finished detecting unauthorized DNS destinations")
