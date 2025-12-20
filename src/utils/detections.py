import logging
import sqlite3

from src.database.allflows import update_all_flows
from src.database.configuration import get_config_settings
from src.database.core import delete_all_records
from src.database.newflows import get_new_flows
from src.database.trafficstats import update_traffic_stats
from src.detect.detect_custom_tag import detect_custom_tag
from src.detect.detect_dead_connections import detect_dead_connections
from src.detect.detect_geolocation_flows import detect_geolocation_flows
from src.detect.detect_high_bandwidth_flows import detect_high_bandwidth_flows
from src.detect.detect_high_risk_ports import detect_high_risk_ports
from src.detect.detect_incorrect_authoritative_dns import (
    detect_incorrect_authoritative_dns,
)
from src.detect.detect_incorrect_ntp_stratum import detect_incorrect_ntp_stratum
from src.detect.detect_many_destinations import detect_many_destinations
from src.detect.detect_new_outbound_connections import detect_new_outbound_connections
from src.detect.detect_port_scanning import detect_port_scanning
from src.detect.detect_reputation_flows import detect_reputation_flows
from src.detect.detect_tor_traffic import detect_tor_traffic
from src.detect.detect_unauthorized_dns import detect_unauthorized_dns
from src.detect.detect_unauthorized_ntp import detect_unauthorized_ntp
from src.detect.detect_vpn_traffic import detect_vpn_traffic
from src.detect.foreign_flows_detection import foreign_flows_detection
from src.detect.local_flows_detection import local_flows_detection
from src.detect.router_flow_detections import router_flows_detection
from src.detect.update_localhosts import update_local_hosts
from src.integrations.geolocation import load_geolocation_data
from src.integrations.reputation import load_reputation_data
from src.utils.locallogging import log_error, log_info


# Function to process data
def process_data():
    logger = logging.getLogger(__name__)

    log_info(logger, "[INFO] Processing started.")

    config_dict = get_config_settings()
    if not config_dict:
        log_error(logger, "[ERROR] Failed to load configuration settings")
        return

    newflows = get_new_flows()
    """Read data from the database and process it."""

    if config_dict["ScheduleProcessor"] == 1:
        try:

            if len(newflows) > 0:
                # delete newflows so collector can write clean to it again as quickly as possible
                log_info(
                    logger, f"[INFO] Fetched {len(newflows)} rows from the database."
                )
                if config_dict["CleanNewFlows"] == 1:
                    delete_all_records("newflows")

                log_info(logger, f"[INFO] Processing {len(newflows)} rows.")

                # Pass the rows to update_all_flows
                update_all_flows(newflows, config_dict)
                update_traffic_stats(newflows, config_dict)

                if config_dict.get("GeolocationFlowsDetection", 0) > 0:
                    geolocation_data = load_geolocation_data()

                if config_dict.get("ReputationListDetection", 0) > 0:
                    reputation_data = load_reputation_data()

                # Proper way to check config values with default of 0
                if config_dict.get("NewHostsDetection", 0) > 0:
                    update_local_hosts(newflows, config_dict)

                log_info(logger, "[INFO] Started removing IgnoreList flows")
                # process ignorelisted entries and remove from src.detection rows
                filtered_rows = [
                    row for row in newflows if "IgnoreList" not in str(row[11])
                ]
                log_info(
                    logger,
                    f"[INFO] Finished removing IgnoreList flows - processing flow count is {len(filtered_rows)}",
                )

                if config_dict.get("RemoveBroadcastFlows", 0) > 0:
                    filtered_rows = [
                        row for row in filtered_rows if "Broadcast" not in str(row[11])
                    ]
                    log_info(
                        logger,
                        f"[INFO] Finished removing Broadcast flows - processing flow count is {len(filtered_rows)}",
                    )

                if config_dict.get("RemoveMulticastFlows", 0) > 0:
                    filtered_rows = [
                        row for row in filtered_rows if "Multicast" not in str(row[11])
                    ]
                    log_info(
                        logger,
                        f"[INFO] Finished removing Multicast flows - processing flow count is {len(filtered_rows)}",
                    )

                if config_dict.get("RemoveLinkLocalFlows", 0) > 0:
                    filtered_rows = [
                        row for row in filtered_rows if "LinkLocal" not in str(row[11])
                    ]
                    log_info(
                        logger,
                        f"[INFO] Finished removing LinkLocal flows - processing flow count is {len(filtered_rows)}",
                    )

                if config_dict.get("NewOutboundDetection", 0) > 0:
                    detect_new_outbound_connections(filtered_rows, config_dict)

                if config_dict.get("RouterFlowsDetection", 0) > 0:
                    router_flows_detection(filtered_rows, config_dict)

                if config_dict.get("ForeignFlowsDetection", 0) > 0:
                    foreign_flows_detection(filtered_rows, config_dict)

                if config_dict.get("LocalFlowsDetection", 0) > 0:
                    local_flows_detection(filtered_rows, config_dict)

                if config_dict.get("BypassLocalDnsDetection", 0) > 0:
                    detect_unauthorized_dns(filtered_rows, config_dict)

                if config_dict.get("BypassLocalNtpDetection", 0) > 0:
                    detect_unauthorized_ntp(filtered_rows, config_dict)

                if config_dict.get("IncorrectAuthoritativeDnsDetection", 0) > 0:
                    detect_incorrect_authoritative_dns(filtered_rows, config_dict)

                if config_dict.get("IncorrectNtpStratumDetection", 0) > 0:
                    detect_incorrect_ntp_stratum(filtered_rows, config_dict)

                if config_dict.get("GeolocationFlowsDetection", 0) > 0:
                    detect_geolocation_flows(
                        filtered_rows, config_dict, geolocation_data
                    )

                if config_dict.get("DeadConnectionDetection", 0) > 0:
                    detect_dead_connections(config_dict)

                if config_dict.get("ReputationListDetection", 0) > 0:
                    detect_reputation_flows(filtered_rows, config_dict, reputation_data)

                if config_dict.get("VpnTrafficDetection", 0) > 0:
                    detect_vpn_traffic(filtered_rows, config_dict)

                if config_dict.get("HighRiskPortDetection", 0) > 0:
                    detect_high_risk_ports(filtered_rows, config_dict)

                if config_dict.get("ManyDestinationsDetection", 0) > 0:
                    detect_many_destinations(filtered_rows, config_dict)

                if config_dict.get("PortScanDetection", 0) > 0:
                    detect_port_scanning(filtered_rows, config_dict)

                if config_dict.get("TorFlowDetection", 0) > 0:
                    detect_tor_traffic(filtered_rows, config_dict)

                if config_dict.get("HighBandwidthFlowDetection", 0) > 0:
                    detect_high_bandwidth_flows(filtered_rows, config_dict)

                if config_dict.get("AlertOnCustomTags", 0) > 0:
                    detect_custom_tag(filtered_rows, config_dict)

        except sqlite3.Error as e:
            log_error(logger, f"[ERROR] Error reading from src.database: {e}")
    log_info(logger, "[INFO] Processing finished.")
