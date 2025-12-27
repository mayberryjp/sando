import logging

from src.notifications.core import handle_alert
from src.utils.locallogging import log_info, log_warn


def detect_incorrect_authoritative_dns(rows, config_dict):
    """
    Detect and alert if a flow originates from a local network (src_ip) and uses
    dst_port 53 (DNS) with a dst_ip that is not in the ApprovedAuthoritativeDnsServersList.

    Args:
        rows: List of flow records.
        config_dict: Dictionary containing configuration settings.
    """
    logger = logging.getLogger(__name__)
    log_info(
        logger,
        "[INFO] Started detecting local DNS servers using unauthorized authoritative DNS",
    )
    # Get the list of approved authoritative DNS servers
    approved_authoritative_dns_servers = set(
        config_dict.get("ApprovedAuthoritativeDnsServersList", "").split(",")
    )
    if not approved_authoritative_dns_servers:
        log_warn(logger, "[WARN] No approved authoritative DNS servers configured")
        return

    APPROVED_LOCAL_DNS_SERVERS_LIST = set(
        config_dict.get("ApprovedLocalDnsServersList", "").split(",")
    )
    # Detect both DNS (port 53) and DNS-over-TLS (port 853)
    filtered_rows = [row for row in rows if row[3] in (53, 853)]

    for row in filtered_rows:
        src_ip, dst_ip, src_port, dst_port, protocol = row[0:5]

        # Check if src_ip is in local networks
        if (
            src_ip in APPROVED_LOCAL_DNS_SERVERS_LIST
            and dst_ip not in approved_authoritative_dns_servers
        ):
            # Check if dst_ip is not in the approved authoritative DNS servers list
            alert_id = f"{src_ip}_{dst_ip}_{dst_port}__IncorrectAuthoritativeDNS"

            log_info(
                logger,
                f"[INFO] Incorrect Authoritative DNS Detected: {src_ip} -> {dst_ip} on port {dst_port}",
            )

            message = (
                f"Incorrect Authoritative DNS Detected:\n"
                f"Source: {src_ip}:{src_port}\n"
                f"Destination: {dst_ip}:{dst_port}\n"
                f"Protocol: {protocol}\n"
                f"Port: {dst_port}"
            )

            handle_alert(
                config_dict,
                "IncorrectAuthoritativeDnsDetection",
                message,
                src_ip,
                row,
                "Incorrect Authoritative DNS Detected",
                dst_ip,
                dst_port,
                alert_id,
            )

    log_info(
        logger,
        "[INFO] Finished detecting local DNS servers using unauthorized authoritative DNS",
    )
