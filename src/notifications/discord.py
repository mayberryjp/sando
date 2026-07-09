import logging
import os
import re

import requests

from src.const import CONST_SITE, IS_CONTAINER, VERSION
from src.database.configuration import get_config_settings
from src.utils.locallogging import log_error, log_info, log_warn

if IS_CONTAINER:
    SITE = os.getenv("SITE", CONST_SITE)


def _discord_enabled(config_dict):
    config_dict = config_dict or {}
    return str(config_dict.get("DiscordEnabled", "")).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    )


def _discord_configured(config_dict):
    config_dict = config_dict or {}
    return bool(config_dict.get("DiscordWebhookUrl")) and _discord_enabled(config_dict)


def _format_alert_message_with_local_description(message, local_ip, local_description):
    message = message or ""
    local_ip = (local_ip or "").strip()
    local_description = (local_description or "").strip()

    if not local_ip or not local_description:
        return message

    pattern = rf"\b{re.escape(local_ip)}\b"
    replacement = f"{local_ip} ({local_description})"
    return re.sub(pattern, replacement, message, count=1)


def send_discord_message(message, flow, local_ip=None, local_description=None):
    """
    Sends a message to Discord using a webhook.

    Args:
        message (str): The message to send.
        flow: The flow data associated with the alert.
    """
    config_dict = get_config_settings()
    logger = logging.getLogger(__name__)

    if not _discord_configured(config_dict):
        return

    try:
        header = f"SANDO Security Alert - {SITE}\n\n"
        enriched_message = _format_alert_message_with_local_description(
            message, local_ip, local_description
        )
        formatted_message = header + enriched_message
        payload = {"content": formatted_message}
        response = requests.post(
            config_dict["DiscordWebhookUrl"], json=payload, timeout=10
        )
        if response.status_code in (200, 204):
            log_info(logger, "[INFO] Discord message sent successfully.")
        else:
            log_error(
                logger,
                f"[ERROR] Failed to send Discord message. Status code: {response.status_code}, Response: {response.text}",
            )
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Exception occurred while sending Discord message: {e}",
        )


def send_test_discord_message():
    """
    Sends a test message to Discord at startup if Discord is enabled and a webhook URL is set.
    """
    logger = logging.getLogger(__name__)
    config_dict = get_config_settings()

    if not _discord_configured(config_dict):
        log_warn(
            logger,
            "[WARN] Discord is disabled or DiscordWebhookUrl is not set. Skipping test Discord message.",
        )
        return

    try:
        message = f"SANDO is online - running version {VERSION} at {SITE}."
        payload = {"content": message}
        response = requests.post(
            config_dict["DiscordWebhookUrl"], json=payload, timeout=10
        )
        if response.status_code in (200, 204):
            log_info(logger, "[INFO] Test Discord message sent successfully.")
        else:
            log_error(
                logger,
                f"[ERROR] Failed to send test Discord message. Status code: {response.status_code}, Response: {response.text}",
            )
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Exception occurred while sending test Discord message: {e}",
        )
