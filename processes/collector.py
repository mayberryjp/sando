import sys
import os
from pathlib import Path
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
sys.path.insert(0, "/database")
from src.netflow import handle_netflow_v5
import logging
from init import *
from database.core import (
    create_table
)

if (IS_CONTAINER):
    SITE = os.getenv("SITE", CONST_SITE)

# Entry point
if __name__ == "__main__":

    logger = logging.getLogger(__name__) 
 
    site_config_path = os.path.join("/database/", f"{SITE}.py")
    
    if not os.path.exists(CONST_CONSOLIDATED_DB):
        log_info(logger, f"[INFO] Consolidated database not found, creating at {CONST_CONSOLIDATED_DB}. We assume this is a first time install. ")
        create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_CONFIG_SQL, "configuration")
        log_info(logger, f"[INFO] No site-specific configuration found at {site_config_path}. This is OK. ")    
        config_dict = init_configurations_from_variable()

    if os.path.exists(site_config_path):
        log_info(logger, f"[INFO] Loading site-specific configuration from {site_config_path}. Leaving this file will overwrite the config database every time, so be careful. It's usually only meant for a one time bootstrapping of a new site with a full config.")
        delete_all_records(CONST_CONSOLIDATED_DB, "configuration")
        config_dict = init_configurations_from_sitepy()
        create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_IGNORELIST_SQL, "ignorelist")
        create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_CUSTOMTAGS_SQL, "customtags")
        import_ignorelists(config_dict)
        import_custom_tags(config_dict)
    else:
        log_info(logger, f"[INFO] No site-specific configuration found at {site_config_path}. This is OK. ")

    store_machine_unique_identifier()
    store_version()
    store_site_name(SITE)
    check_update_database_schema(config_dict)

    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_SERVICES_SQL, "services")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_ACTIONS_SQL, "actions")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_CONFIG_SQL, "configuration")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_IGNORELIST_SQL, "ignorelist")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_CUSTOMTAGS_SQL, "customtags")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_TRAFFICSTATS_SQL, "trafficstats")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_ALERTS_SQL, "alerts")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_ALLFLOWS_SQL, "allflows")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_NEWFLOWS_SQL, "newflows")
    delete_all_records(CONST_CONSOLIDATED_DB,"newflows")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_LOCALHOSTS_SQL, "localhosts")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_GEOLOCATION_SQL, "geolocation")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_REPUTATIONLIST_SQL, "reputationlist")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_TORNODES_SQL, "tornodes")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_DNSQUERIES_SQL, "dnsqueries")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_IPASN_SQL, "ipasn")

    config_dict = get_config_settings()

    if not config_dict:
        log_error(logger, "[ERROR] Failed to load configuration settings")
        exit(1)

    log_info(logger, f"[INFO] Current configuration at start, config will refresh automatically every time processor runs:\n {dump_json(config_dict)}")
    log_info(logger, f"[INFO] Starting NetFlow v5 collector {VERSION} at {SITE}")
    if config_dict['StartCollector'] == 1:
        # Start the collector
        handle_netflow_v5()
