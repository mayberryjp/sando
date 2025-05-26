import requests
from src.const import IS_CONTAINER, VERSION, CONST_SITE
from database.configuration import get_config_settings
import os
import logging
from src.locallogging import log_info, log_error, log_warn

if (IS_CONTAINER):
    SITE = os.getenv("SITE", CONST_SITE)




def send_telegram_message(message, flow):
    """
    Sends a message to a Telegram group chat.

    Args:
        message (str): The message to send.
        flow: The flow data associated with the alert.
    """
    config_dict = get_config_settings()
    logger = logging.getLogger(__name__)
    if config_dict['TelegramBotToken'] and config_dict['TelegramChatId'] and config_dict['TelegramEnabled']:
        try:
            
            # Create header with warning emoji and site name
            header = f"⚠️ HomelabIDS Security Alert - {SITE}\n\n"
            formatted_message = header + message

            url = f"https://api.telegram.org/bot{config_dict['TelegramBotToken']}/sendMessage"
            payload = {
                "chat_id": config_dict['TelegramChatId'],
                "text": formatted_message,
                "parse_mode": "HTML"
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                log_info(logger, f"[INFO] Telegram message sent successfully.")
            else:
                log_error(logger, f"[ERROR] Failed to send Telegram message. Status code: {response.status_code}, Response: {response.text}")
        except Exception as e:
            log_error(logger, f"[ERROR] Exception occurred while sending Telegram message: {e}")


def send_test_telegram_message():
    """
    Sends a test message to a Telegram group chat at startup if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set.
    """
    logger = logging.getLogger(__name__)
    config_dict= get_config_settings()

    
    if config_dict['TelegramBotToken'] and config_dict['TelegramChatId'] and config_dict['TelegramEnabled']:
        try:
            message = f"HomelabIDS is online - running version {VERSION} at {SITE}."
            url = f"https://api.telegram.org/bot{config_dict['TelegramBotToken']}/sendMessage"
            payload = {
                "chat_id": config_dict['TelegramChatId'],
                "text": message,
                "parse_mode": "HTML"
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                log_info(logger, f"[INFO] Test Telegram message sent successfully.")
            else:
                log_error(logger, f"[ERROR] Failed to send test Telegram message. Status code: {response.status_code}, Response: {response.text}")
        except Exception as e:
            log_error(logger, f"[ERROR] Exception occurred while sending test Telegram message: {e}")
    else:
        log_warn(logger, f"[WARN] TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set. Skipping test Telegram message.")

