import logging

from src.database.localhosts import get_localhosts_all
from src.database.trafficstats import get_all_ips_traffic_status
from src.notifications.core import handle_alert
from src.utils.locallogging import log_info


def detect_offline_hosts(config_dict):
    """
    Alert for localhosts that have offline detection enabled and no recent trafficstats.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting offline host detection.")

    localhosts = get_localhosts_all()
    if not localhosts:
        log_info(logger, "[INFO] No localhosts found for offline host detection.")
        return

    ip_traffic_status = get_all_ips_traffic_status()

    for host in localhosts:
        ip_address = host.get("ip_address")
        if not ip_address:
            continue

        if host.get("alert_if_offline", 1) not in (1, True, "1"):
            continue

        if ip_traffic_status.get(ip_address, False):
            continue

        alert_id = f"{ip_address}_OfflineHostDetection"
        message = (
            f"Offline Host Detected:\n"
            f"IP Address: {ip_address}\n"
            f"No trafficstats found in the recent traffic window"
        )

        log_info(logger, f"[INFO] Offline host detected: {ip_address}")
        handle_alert(
            config_dict,
            "OfflineHostDetection",
            message,
            ip_address,
            host,
            "Offline Host Detected",
            "No recent trafficstats",
            "",
            alert_id,
        )

    log_info(logger, "[INFO] Finished offline host detection.")
