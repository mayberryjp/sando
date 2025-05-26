import requests
from src.const import IS_CONTAINER, VERSION, CONST_SITE
from database.configuration import get_config_settings
import os
import logging
from src.locallogging import log_info, log_error, log_warn
from database.alerts import log_alert_to_db
from notifications.telegram import send_telegram_message
from database.localhosts import get_localhost_by_ip

def handle_alert(config_dict, detection_key, telegram_message, local_ip, original_flow, alert_category, enrichment_1, enrichment_2, alert_id_hash):
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
    
    # Only proceed if detection is enabled
    if detection_level >= 1:
        # Check if alerts are enabled for this IP address
        localhost_info = get_localhost_by_ip(local_ip)
        alerts_enabled = True  # Default to True if localhost not found
        
        if localhost_info:
            alerts_enabled = localhost_info[16]
            
        # Log the alert to the database regardless of alerts_enabled status
        insert_or_update = log_alert_to_db(local_ip, original_flow, alert_category, 
                                          enrichment_1, enrichment_2, alert_id_hash, False)
        
        # Only send Telegram notifications if alerts are enabled for this IP
        if alerts_enabled and detection_level >= 2:
            if insert_or_update == "insert":
                log_info(logger, f"[INFO] Sending Telegram alert for {local_ip} (new alert)")
                send_telegram_message(telegram_message, original_flow)
            elif insert_or_update == "update" and detection_level == 3:
                log_info(logger, f"[INFO] Sending Telegram alert for {local_ip} (updated alert)")
                send_telegram_message(telegram_message, original_flow)
            elif not insert_or_update:
                log_warn(logger, f"[WARN] Failed to log alert for {local_ip}, Telegram message not sent")
        elif not alerts_enabled and detection_level >= 2:
            log_info(logger, f"[INFO] Telegram alert suppressed for {local_ip} (alerts_enabled=False)")

        return insert_or_update

    return None