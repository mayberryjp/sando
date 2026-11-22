import logging
import sqlite3
import time

from src.const import VERSION
from src.database.configuration import get_config_settings, update_flow_metrics
from src.database.core import connect_to_db, disconnect_from_db
from src.utils.ipfix import handle_ipfix
from src.utils.locallogging import log_error, log_info


def collector_dependencies_ready():
    for table in ("configuration", "ignorelist", "newflows", "localhosts"):
        conn = connect_to_db(table)
        if not conn:
            return False
        try:
            conn.execute(f"SELECT 1 FROM {table} LIMIT 0")
        except sqlite3.Error as exc:
            log_error(logging.getLogger(__name__), f"[ERROR] IPFIX dependency {table} not ready: {exc}")
            return False
        finally:
            disconnect_from_db(conn)
    return True


def main():
    logger = logging.getLogger(__name__)
    # Only collector bootstraps configuration/schema; do not repeat destructive initialization.
    log_info(logger, "[INFO] IPFIX process waiting 30 seconds for collector initialization")
    time.sleep(30)
    while True:
        if collector_dependencies_ready():
            config_dict = get_config_settings()
            if (
                not config_dict
                or "StartIpfixCollector" not in config_dict
                or int(config_dict.get("CollectorInitialized", 0)) != 1
            ):
                log_error(logger, "[ERROR] IPFIX configuration not ready; retrying in 30 seconds")
            elif int(config_dict["StartIpfixCollector"]) == 1:
                break
            else:
                update_flow_metrics(0, 0, 0, source="ipfix")
                log_info(logger, "[INFO] IPFIX collector disabled; checking again in 30 seconds")
        else:
            log_error(logger, "[ERROR] Waiting for IPFIX database dependencies; retrying in 30 seconds")
        time.sleep(30)
    log_info(logger, f"[INFO] Starting IPFIX v10 collector {VERSION}")
    handle_ipfix()


if __name__ == "__main__":
    main()
