import logging
import os
import time

from src.const import CONST_REINITIALIZE_DB, IS_CONTAINER
from src.database.configuration import get_config_settings
from src.notifications.telegram import (
    send_test_telegram_message,
)  # Import send_test_telegram_message from src.notifications.py
from src.utils.detections import process_data
from src.utils.locallogging import log_error, log_info

if IS_CONTAINER:
    REINITIALIZE_DB = os.getenv("REINITIALIZE_DB", CONST_REINITIALIZE_DB)

if __name__ == "__main__":

    logger = logging.getLogger(__name__)

    STARTUP_DELAY = 30
    log_info(
        logger,
        f"[INFO] Processor process pausing {STARTUP_DELAY} seconds before starting up",
    )
    # wait a bit for startup so collector can init configurations
    time.sleep(STARTUP_DELAY)

    config_dict = get_config_settings()

    log_info(logger, "[INFO] Processor started.")

    send_test_telegram_message()

    while True:

        config_dict = get_config_settings()
        if not config_dict:
            log_error(logger, "[ERROR] Failed to load configuration settings")
            exit(1)

        PROCESS_RUN_INTERVAL = config_dict.get("ProcessRunInterval", 60)
        log_info(
            logger,
            f"[INFO] Process run interval set to {PROCESS_RUN_INTERVAL} seconds.",
        )

        process_data()
        time.sleep(PROCESS_RUN_INTERVAL)
