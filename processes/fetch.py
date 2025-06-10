import sys
import os
from pathlib import Path
import threading
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
sys.path.insert(0, "/database")
import time
import logging
from integrations.tor import update_tor_nodes
from integrations.geolocation import create_geolocation_db
from src.client import upload_all_client_definitions, upload_configuration, upload_database_metrics
from integrations.reputation import import_reputation_list
from integrations.piholedns import get_pihole_ftl_logs
from integrations.services import create_services_db
from integrations.ipasn import create_asn_database
from integrations.dns import resolve_empty_dns_responses
from src.const import CONST_REINITIALIZE_DB, CONST_CONSOLIDATED_DB, IS_CONTAINER
from init import *

if (IS_CONTAINER):
    REINITIALIZE_DB=os.getenv("REINITIALIZE_DB", CONST_REINITIALIZE_DB)

def pihole_logs_thread():
    """
    Thread function to fetch Pihole DNS logs every hour.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting hourly Pihole DNS logs fetch thread")
    config_dict = get_config_settings()

    # Hourly interval in seconds
    pihole_fetch_interval = config_dict.get('PiholeFetchInterval', 3600)
    
    while True:
        try:
            config_dict = get_config_settings()

            if not config_dict:
                log_error(logger, "[ERROR] Failed to load configuration settings in Pihole fetch thread")
                time.sleep(60)  # Wait a minute before retrying
                continue
                
            if config_dict.get('StorePiHoleDnsQueryHistory', 0) > 0:
                log_info(logger, "[INFO] Fetching Pihole DNS query history (hourly)...")
                fetch_size = config_dict.get('PiHoleDnsFetchRecordSize', 10000)
                get_pihole_ftl_logs(fetch_size, config_dict)
                log_info(logger, "[INFO] Pihole DNS query history fetch completed")

            if config_dict.get('PerformDnsResponseLookupsForInvestigations', 0) > 0 and config_dict.get('DnsResponseLookupResolver', None):
                log_info(logger, "[INFO] Preparing to resolve unresolved dns entries...")
                resolve_empty_dns_responses(config_dict)
                log_info(logger, "[INFO] Pihole DNS query history fetch completed")

        except Exception as e:
            log_error(logger, f"[ERROR] Error during hourly Pihole data fetch: {e}")
        
        # Wait for the next interval
        log_info(logger, f"[INFO] Pihole thread sleeping for {pihole_fetch_interval} seconds")
        time.sleep(pihole_fetch_interval)

def main():
    """
    Main program to fetch and update external data at a fixed interval.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting external data fetcher")
    config_dict = get_config_settings()
    if not config_dict:
        log_error(logger, "[ERROR] Failed to load configuration settings")
        exit(1)

    fetch_interval = config_dict.get('IntegrationFetchInterval', 86400)
    
    # Start the Pihole logs fetch thread
    pihole_thread = threading.Thread(target=pihole_logs_thread, daemon=True)
    pihole_thread.start()
    log_info(logger, "[INFO] Started hourly Pihole DNS logs fetch thread")
    
    while True:
        try:
            log_info(logger,"[INFO] Deleting old traffic stats...")
            delete_old_traffic_stats()
            log_info(logger, "[INFO] Finished deleting old traffic stats.")
        except Exception as e:
            log_error(logger, f"[ERROR] Error during deleting old traffic stats: {e}")

        config_dict = get_config_settings()
        if not config_dict:
            log_error(logger, "[ERROR] Failed to load configuration settings")
            exit(1)
        # Call the update_tor_nodes function

        try: 
            if config_dict.get('SendDeviceClassificationsToHomelabApi', 0) > 0:
                log_info(logger, "[INFO] Sending device classifications to Homelab API...")
                upload_all_client_definitions()
                log_info(logger, "[INFO] Device classification upload finished.")
        except Exception as e:
            log_error(logger, f"[ERROR] Error during data fetch: {e}")

        try: 
            if config_dict.get('SendConfigurationToCloudApi', 0) > 0:
                log_info(logger, "[INFO] Sending instance configuration to Homelab API...")
                upload_configuration()
                log_info(logger, "[INFO] Instance configuration upload finished.")
                log_info(logger, "[INFO] Sending database metrics to Homelab API...")
                upload_database_metrics()
                log_info(logger, "[INFO] Database metrics upload finished.")
        except Exception as e:
            log_error(logger, f"[ERROR] Error during data fetch: {e}")

        try:
            if config_dict.get("ImportAsnDatabase",0) > 0:
                log_info(logger,"[INFO] Retrieving IP2ASN Database...")
                create_asn_database()
                log_info(logger, "[INFO] IP2ASN update finished.")
        except Exception as e:
            log_error(logger, f"[ERROR] Error during data fetch: {e}")

        try: 
            if config_dict.get('TorFlowDetection',0) > 0:
                log_info(logger, "[INFO] Fetching and updating Tor node list...")
                update_tor_nodes(config_dict)
                log_info(logger, "[INFO] Tor node list update finished.")
        except Exception as e:
            log_error(logger, f"[ERROR] Error during data fetch: {e}")

        try: 
            if config_dict.get('GeolocationFlowsDetection',0) > 0:
                log_info(logger, "[INFO] Fetching and updating geolocation data..")
                create_geolocation_db()
                log_info(logger, "[INFO] Geolocation update finished.")
        except Exception as e:
            log_error(logger, f"[ERROR] Error during data fetch: {e}")

        try: 
            if config_dict.get('ReputationListDetection', 0) > 0:
                log_info(logger, "[INFO] Fetching and updating reputation list...")
                import_reputation_list(config_dict)
                log_info(logger, "[INFO] Reputation list update finished.")
        except Exception as e:
            log_error(logger, f"[ERROR] Error during data fetch: {e}")

        try: 
            if config_dict.get('ImportServicesList', 0) > 0:
                log_info(logger, "[INFO] Fetching and updating services list...")
                create_services_db()
                log_info(logger, "[INFO] Services list download finished.")
        except Exception as e:
            log_error(logger, f"[ERROR] Error during data fetch: {e}")

        log_info(logger,"[INFO] Creating DNS Key Value Pairs..")
        create_dns_key_value()
        log_info(logger, "[INFO] DNS Key Value Pairs creation finished.")

        log_info(logger,"[INFO] Populating Explore Master Flow Table..")
        bulk_populate_master_flow_view()
        log_info(logger, "[INFO] Populating Explore Master Flow Table finished.")


        # Wait for the next interval
        log_info(logger, f"[INFO] Sleeping for {fetch_interval} seconds before the next fetch.")
        time.sleep(fetch_interval)

if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    STARTUP_DELAY = 30
    log_info(logger,f"[INFO] Starting fetcher, waiting {STARTUP_DELAY} seconds before starting processing")
    time.sleep(STARTUP_DELAY)
    main()