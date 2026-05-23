import json
import logging

from src.notifications.core import handle_alert
from src.utils.locallogging import log_info, log_warn


def detect_rogue_dhcp(rows, config_dict):
    """
    Detect rogue DHCP servers — devices sending DHCP responses (src_port=67, dst_port=68)
    that are not in the list of authorized DHCP servers.

    Authorized DHCP servers are derived from:
      - The 'router' field of each scope in LocalNetworks
      - The 'ApprovedDhcpServersList' config key (comma-separated)

    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting rogue DHCP server detection")

    # Build the set of authorized DHCP server IPs
    approved_dhcp_servers = set()

    # Add any explicitly configured servers
    explicit = config_dict.get("ApprovedDhcpServersList", "")
    if explicit:
        approved_dhcp_servers.update(
            s.strip() for s in explicit.split(",") if s.strip()
        )

    # Add routers from LocalNetworks scopes (they are typically also the DHCP server)
    try:
        scopes_raw = config_dict.get("LocalNetworks", "[]")
        scopes = json.loads(scopes_raw)
        for scope in scopes:
            router = scope.get("router")
            if router:
                approved_dhcp_servers.add(router)
    except Exception as e:
        log_warn(logger, f"[WARN] Could not parse LocalNetworks for DHCP servers: {e}")

    if not approved_dhcp_servers:
        log_warn(
            logger,
            "[WARN] No authorized DHCP servers configured — skipping rogue DHCP detection",
        )
        return

    # DHCP responses: server sends from port 67, client receives on port 68, UDP protocol 17
    dhcp_response_rows = [
        row for row in rows if row[2] == 67 and row[3] == 68 and row[4] == 17
    ]

    for row in dhcp_response_rows:
        src_ip, dst_ip, src_port, dst_port, protocol = row[0:5]

        if src_ip not in approved_dhcp_servers:
            alert_id = f"{src_ip}__RogueDhcpServer"

            log_info(
                logger,
                f"[INFO] Rogue DHCP Server Detected: {src_ip} sending DHCP responses (port 67 -> 68)",
            )

            message = (
                f"Rogue DHCP Server Detected:\n"
                f"Source: {src_ip}:{src_port}\n"
                f"Destination: {dst_ip}:{dst_port}\n"
                f"Protocol: UDP\n"
                f"A device is responding to DHCP requests but is not in the authorized DHCP server list."
            )

            handle_alert(
                config_dict,
                "RogueDhcpDetection",
                message,
                src_ip,
                row,
                "Rogue DHCP Server Detected",
                dst_ip,
                dst_port,
                alert_id,
            )

    log_info(logger, "[INFO] Finished rogue DHCP server detection")
