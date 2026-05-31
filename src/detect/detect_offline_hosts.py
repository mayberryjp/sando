import logging

from src.database.localhosts import get_localhosts_all
from src.database.trafficstats import get_all_ips_traffic_status
from src.notifications.core import handle_alert
from src.utils.locallogging import log_info


def _enabled(value):
    if isinstance(value, str):
        return value.strip().lower() not in ("0", "false", "no", "off", "")
    return bool(value)


def detect_offline_hosts(config_dict):
    """
    Detect local hosts that have not had trafficstats entries in the recent traffic window.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Started offline host detection")

    localhosts = get_localhosts_all()
    if not localhosts:
        log_info(logger, "[INFO] No localhosts found for offline host detection")
        return

    ip_traffic_status = get_all_ips_traffic_status()

    for host in localhosts:
        ip_address = host.get("ip_address")
        if not ip_address:
            continue

        if not _enabled(host.get("alert_if_offline", 1)):
            continue

        if ip_traffic_status.get(ip_address, False):
            continue

        alert_id = f"{ip_address}_OfflineHostDetection"
        message = (
            f"Offline Host Detected:\n"
            f"IP Address: {ip_address}\n"
            f"Reason: No recent traffic statistics found\n"
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

    log_info(logger, "[INFO] Finished offline host detection")
