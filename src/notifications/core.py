import logging

from src.database.alerts import log_alert_to_db
from src.database.localhosts import get_localhost_by_ip
from src.notifications.discord import send_discord_message
from src.notifications.telegram import send_telegram_message
from src.utils.locallogging import log_info, log_warn


def handle_alert(
    config_dict,
    detection_key,
    telegram_message,
    local_ip,
    original_flow,
    alert_category,
    enrichment_1,
    enrichment_2,
    alert_id_hash,
):
    """
    Handle alerting logic based on the configuration level and alerts_enabled status.

    Args:
        config_dict (dict): Configuration dictionary.
        detection_key (str): The key in the configuration dict for the detection type (e.g., "NewOutboundDetection").
        telegram_message (str): The alert message to send.
        local_ip (str): Local IP address.
        original_flow (str): The original flow data.
        alert_category (str): Category of the alert.
        enrichment_1 (str): First enrichment data.
        enrichment_2 (str): Second enrichment data.
        alert_id_hash (str): Unique identifier hash for the alert.

    Returns:
        str: "insert", "update", or None based on the operation performed.
    """
    logger = logging.getLogger(__name__)

    # Get the detection level from the configuration
    detection_level = config_dict.get(detection_key, 0)

    # Initialize localhost_info before first use
    localhost_info = get_localhost_by_ip(local_ip)
    if localhost_info and len(localhost_info) > 20 and localhost_info[20] == 1:
        log_info(
            logger,
            f"[INFO] Alert logic skipped for {local_ip} host is excluded from alerting",
        )
        return None

    # Only proceed if detection is enabled
    if detection_level >= 1:
        # Check if alerts are enabled for this IP address
        alerts_enabled = True  # Default to True if localhost not found

        if localhost_info:
            alerts_enabled = localhost_info[16]

        # Log the alert to the database regardless of alerts_enabled status
        insert_or_update = log_alert_to_db(
            local_ip,
            original_flow,
            alert_category,
            enrichment_1,
            enrichment_2,
            alert_id_hash,
            False,
        )

        # Only send notifications if alerts are enabled for this IP
        if alerts_enabled and detection_level >= 2:
            if insert_or_update == "insert":
                log_info(
                    logger,
                    f"[INFO] Sending alert notifications for {local_ip} (new alert)",
                )
                send_telegram_message(telegram_message, original_flow)
                local_description = (
                    localhost_info[12]
                    if localhost_info and len(localhost_info) > 12
                    else ""
                )
                send_discord_message(
                    telegram_message,
                    original_flow,
                    local_ip=local_ip,
                    local_description=local_description,
                )
            elif insert_or_update == "update" and detection_level == 3:
                log_info(
                    logger,
                    f"[INFO] Sending alert notifications for {local_ip} (updated alert)",
                )
                send_telegram_message(telegram_message, original_flow)
                local_description = (
                    localhost_info[12]
                    if localhost_info and len(localhost_info) > 12
                    else ""
                )
                send_discord_message(
                    telegram_message,
                    original_flow,
                    local_ip=local_ip,
                    local_description=local_description,
                )
            elif not insert_or_update:
                log_warn(
                    logger,
                    f"[WARN] Failed to log alert for {local_ip}, notifications not sent",
                )
        elif not alerts_enabled and detection_level >= 2:
            log_info(
                logger,
                f"[INFO] Alert notifications suppressed for {local_ip} (alerts_enabled=False)",
            )

        return insert_or_update

    return None
