import logging

from src.notifications.core import handle_alert
from src.utils.locallogging import log_info, log_warn


def detect_incorrect_ntp_stratum(rows, config_dict):
    """
    Detect and alert if a flow originates from a local network (src_ip) and uses
    dst_port 123 (NTP) with a dst_ip that is not in the ApprovedNtpStratumServersList.

    Args:
        rows: List of flow records.
        config_dict: Dictionary containing configuration settings.
    """
    logger = logging.getLogger(__name__)
    log_info(
        logger,
        "[INFO] Started detecting local NTP servers using unauthorized stratum NTP destinations",
    )
    # Get the list of approved NTP stratum servers
    approved_ntp_stratum_servers = set(
        config_dict.get("ApprovedNtpStratumServersList", "").split(",")
    )
    if not approved_ntp_stratum_servers:
        log_warn(logger, "[WARN] No approved NTP stratum servers configured")
        return

    APPROVED_LOCAL_NTP_SERVERS_LIST = set(
        config_dict.get("ApprovedLocalNtpServersList", "").split(",")
    )
    filtered_rows = [row for row in rows if row[3] == 123]

    for row in filtered_rows:
        src_ip, dst_ip, src_port, dst_port, protocol = row[0:5]

        # Check if src_ip is in local networks
        if (
            src_ip in APPROVED_LOCAL_NTP_SERVERS_LIST
            and dst_ip not in approved_ntp_stratum_servers
        ):
            # Check if dst_ip is not in the approved NTP stratum servers list
            alert_id = f"{src_ip}_{dst_ip}__IncorrectNTPStratum"

            log_info(
                logger, f"[INFO] Incorrect NTP Stratum Detected: {src_ip} -> {dst_ip}"
            )

            message = (
                f"Incorrect NTP Stratum Detected:\n"
                f"Source: {src_ip}:{src_port}\n"
                f"Destination: {dst_ip}:{dst_port}\n"
                f"Protocol: {protocol}"
            )

            handle_alert(
                config_dict,
                "IncorrectNtpStratrumDetection",
                message,
                src_ip,
                row,
                "Incorrect NTP Stratum Detected",
                dst_ip,
                dst_port,
                alert_id,
            )

    log_info(
        logger,
        "[INFO] Finished detecting local NTP servers using unauthorized stratum NTP destinations",
    )
