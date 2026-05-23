import logging
import os
import sys
import time
from pathlib import Path

from src.const import (
    CONST_ACTIONS_DB,
    CONST_CONFIGURATION_DB,
    CONST_CREATE_ACTIONS_SQL,
    CONST_CREATE_ALERTS_SQL,
    CONST_CREATE_ALLFLOWS_SQL,
    CONST_CREATE_CONFIG_SQL,
    CONST_CREATE_CUSTOMTAGS_SQL,
    CONST_CREATE_DBPERFORMANCE_SQL,
    CONST_CREATE_DNSKEYVALUE_SQL,
    CONST_CREATE_DNSQUERIES_SQL,
    CONST_CREATE_EXPLORE_SQL,
    CONST_CREATE_GEOLOCATION_SQL,
    CONST_CREATE_IGNORELIST_SQL,
    CONST_CREATE_IPASN_SQL,
    CONST_CREATE_LOCALHOSTS_SQL,
    CONST_CREATE_NEWFLOWS_SQL,
    CONST_CREATE_REPUTATIONLIST_SQL,
    CONST_CREATE_SERVICES_SQL,
    CONST_CREATE_TORNODES_SQL,
    CONST_CREATE_TRAFFICSTATS_SQL,
    CONST_DATABASE_SCHEMA_VERSION,
    CONST_SITE,
    IS_CONTAINER,
    VERSION,
)
from src.database.actions import insert_action
from src.database.common import (
    check_update_database_schema,
    init_configurations_from_sitepy,
    init_configurations_from_variable,
    store_machine_unique_identifier,
    store_site_name,
    store_version,
)
from src.database.configuration import get_config_settings
from src.database.core import create_table, delete_all_records, delete_aged_dbperformance
from src.database.customtags import import_custom_tags
from src.database.ignorelist import (
    import_ignorelists,
    whitelist_approved_dns_servers,
    whitelist_approved_ntp_servers,
)
from src.utils.locallogging import dump_json, log_error, log_info, log_warn
from src.utils.netflow import handle_netflow_v5

if IS_CONTAINER:
    SITE = os.getenv("SITE", CONST_SITE)

sys.path.insert(0, "/database")
parent_dir = Path(__file__).resolve().parent.parent


# Entry point
if __name__ == "__main__":

    logger = logging.getLogger(__name__)

    site_config_path = os.path.join("/database/", f"{SITE}.py")
    database_path = os.path.join("/database/", CONST_CONFIGURATION_DB)
    schema_file_path = os.path.join(parent_dir, "/database", "database.schema")

    if not os.path.exists(CONST_CONFIGURATION_DB):
        log_info(
            logger,
            f"[INFO] Configuration database not found, creating at {CONST_CONFIGURATION_DB}. We assume this is a first time install. ",
        )
        time.sleep(5)
        create_table(CONST_CREATE_CONFIG_SQL, "configuration")
        time.sleep(5)
        config_dict = init_configurations_from_variable()

    if not os.path.exists(CONST_ACTIONS_DB):
        log_info(
            logger,
            f"[INFO] Actions database not found, creating at {CONST_ACTIONS_DB}. We assume this is a first time install. ",
        )
        create_table(CONST_CREATE_ACTIONS_SQL, "actions")
        os.makedirs(os.path.dirname(schema_file_path), exist_ok=True)
        with open(schema_file_path, "w") as f:
            f.write(str(CONST_DATABASE_SCHEMA_VERSION))
        insert_action(
            "If you just performed initial installation then detections are not enabled by default. Please navigate to Settings -> Processes and turn on Detection Processing and to Settings -> Detections to turn on New Host Detections. You can then customize the system further."
        )

    if os.path.exists(site_config_path):
        log_info(
            logger,
            f"[INFO] Loading site-specific configuration from {site_config_path}. Leaving this file will overwrite the config database every time, so be careful. It's usually only meant for a one time bootstrapping of a new site with a full config.",
        )
        delete_all_records("configuration")
        config_dict = init_configurations_from_sitepy()
        create_table(CONST_CREATE_IGNORELIST_SQL, "ignorelist")
        create_table(CONST_CREATE_CUSTOMTAGS_SQL, "customtags")
        import_ignorelists(config_dict)
        import_custom_tags(config_dict)
    else:
        log_info(
            logger,
            f"[INFO] No site-specific configuration found at {site_config_path}. This is OK. ",
        )

    create_table(CONST_CREATE_CONFIG_SQL, "configuration")
    create_table(CONST_CREATE_LOCALHOSTS_SQL, "localhosts")
    create_table(CONST_CREATE_SERVICES_SQL, "services")
    create_table(CONST_CREATE_ACTIONS_SQL, "actions")
    create_table(CONST_CREATE_CONFIG_SQL, "configuration")
    create_table(CONST_CREATE_IGNORELIST_SQL, "ignorelist")
    create_table(CONST_CREATE_CUSTOMTAGS_SQL, "customtags")
    create_table(CONST_CREATE_TRAFFICSTATS_SQL, "trafficstats")
    create_table(CONST_CREATE_ALERTS_SQL, "alerts")
    create_table(CONST_CREATE_ALLFLOWS_SQL, "allflows")
    create_table(CONST_CREATE_NEWFLOWS_SQL, "newflows")
    delete_all_records("newflows")
    create_table(CONST_CREATE_LOCALHOSTS_SQL, "localhosts")
    create_table(CONST_CREATE_GEOLOCATION_SQL, "geolocation")
    create_table(CONST_CREATE_REPUTATIONLIST_SQL, "reputationlist")
    create_table(CONST_CREATE_TORNODES_SQL, "tornodes")
    create_table(CONST_CREATE_DNSQUERIES_SQL, "dnsqueries")
    create_table(CONST_CREATE_IPASN_SQL, "ipasn")
    create_table(CONST_CREATE_EXPLORE_SQL, "explore")
    create_table(CONST_CREATE_DNSKEYVALUE_SQL, "dnskeyvalue")
    create_table(CONST_CREATE_DBPERFORMANCE_SQL, "dbperformance")

    store_machine_unique_identifier()
    store_version()
    store_site_name(SITE)

    config_dict = get_config_settings()

    log_info(
        logger,
        f"[INFO] Current configuration at start, config will refresh automatically every time processor runs:\n {dump_json(config_dict)}",
    )

    check_update_database_schema(config_dict)
    delete_aged_dbperformance(days=180)

    # Add NTP whitelists if bypass detection is enabled and servers are configured
    if (
        config_dict.get("BypassLocalNtpDetection", 0) == 1
        and config_dict.get("ApprovedLocalNtpServersList", "")
        and config_dict.get("ApprovedNtpStratumServersList", "")
    ):

        # Create NTP whitelists
        if whitelist_approved_ntp_servers(config_dict):
            log_info(logger, "[INFO] NTP whitelists successfully created.")
        else:
            log_warn(logger, "[WARN] Some NTP whitelists could not be created.")

    # Add DNS whitelists if bypass detection is enabled and servers are configured
    if (
        config_dict.get("BypassLocalDnsDetection", 0) == 1
        and config_dict.get("ApprovedLocalDnsServersList", "")
        and config_dict.get("ApprovedAuthoritativeDnsServersList", "")
    ):

        # Create DNS whitelists
        if whitelist_approved_dns_servers(config_dict):
            log_info(logger, "[INFO] DNS whitelists successfully created.")
        else:
            log_warn(logger, "[WARN] Some DNS whitelists could not be created.")

    if not config_dict:
        log_error(logger, "[ERROR] Failed to load configuration settings")
        exit(1)

    log_info(logger, f"[INFO] Starting NetFlow v5 collector {VERSION} at {SITE}")
    if config_dict["StartCollector"] == 1:
        # Start the collector
        handle_netflow_v5()
