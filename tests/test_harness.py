import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *

from database.core import create_table, connect_to_db, delete_all_records, get_row_count

from src.client import export_client_definition
from integrations.geolocation import load_geolocation_data, create_geolocation_db
from integrations.dns import dns_lookup, resolve_empty_dns_responses  # Import the dns_lookup function from dns.py
from integrations.piholedhcp import get_pihole_dhcp_leases, get_pihole_network_devices
from integrations.nmap_fingerprint import os_fingerprint
from integrations.reputation import import_reputation_list, load_reputation_data
from integrations.tor import update_tor_nodes
from integrations.piholedns import get_pihole_ftl_logs
from integrations.ipasn import create_asn_database
from integrations.services import create_services_db, get_all_services
from integrations.threatscore import calculate_update_threat_scores
from src.tags import apply_tags

from src.detections import (
    update_local_hosts,
    detect_new_outbound_connections,
    router_flows_detection,
    foreign_flows_detection,
    local_flows_detection,
    detect_geolocation_flows,
    detect_dead_connections,
    detect_unauthorized_ntp,
    detect_unauthorized_dns,
    detect_incorrect_authoritative_dns,
    detect_incorrect_ntp_stratum,
    detect_reputation_flows,
    detect_vpn_traffic, detect_high_risk_ports,
    detect_many_destinations,
    detect_port_scanning,
    detect_tor_traffic,
    detect_high_bandwidth_flows,
    detect_custom_tag
)

OUTPUT_FOLDER = "tests/client_definitions"

def save_client_data(ip_address, data):
    """
    Save client data to a JSON file.

    Args:
        ip_address (str): The IP address used as the filename.
        data (dict): The client data to save.
    """
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)

    file_path = os.path.join(OUTPUT_FOLDER, f"{ip_address}.json")
    try:
        with open(file_path, "w") as file:
            json.dump(data, file, indent=4)
        logging.info(f"Saved client data for {ip_address} to {file_path}")
    except IOError as e:
        logging.error(f"Failed to save client data for {ip_address}: {e}")




def classify_client(machine_identifier, client_data):
    """
    Send client data to the classification API and get classification results.
    
    Args:
        machine_identifier (str): Unique identifier for the machine
        client_data (dict): Client data JSON to be classified
        
    Returns:
        dict: Classification response or None if request failed
    """
    logger = logging.getLogger(__name__)

    api_url = f"http://api.homelabids.com:8045/api/classify/{machine_identifier}"
    
    try:
        log_info(logger, f"[INFO] Sending client data to classification API for machine {machine_identifier}")
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Make the API request
        response = requests.post(
            api_url,
            json=client_data,
            headers=headers,
            timeout=30  # Timeout after 30 seconds
        )
        
        # Check for successful response
        response.raise_for_status()
        
        # Parse the JSON response
        classification_result = response.json()
        log_info(logger, f"[INFO] Successfully received classification for machine {machine_identifier}")
        
        return classification_result
        
    except requests.exceptions.HTTPError as e:
        log_error(logger, f"[ERROR] HTTP error when classifying machine {machine_identifier}: {e}")
        log_error(logger, f"[ERROR] Response content: {e.response.text if hasattr(e, 'response') else 'No response'}")
    except requests.exceptions.ConnectionError as e:
        log_error(logger, f"[ERROR] Connection error when classifying machine {machine_identifier}: {e}")
    except requests.exceptions.Timeout as e:
        log_error(logger, f"[ERROR] Timeout when classifying machine {machine_identifier}: {e}")
    except requests.exceptions.RequestException as e:
        log_error(logger, f"[ERROR] Request error when classifying machine {machine_identifier}: {e}")
    except json.JSONDecodeError as e:
        log_error(logger, f"[ERROR] Invalid JSON in classification response for machine {machine_identifier}: {e}")
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error when classifying machine {machine_identifier}: {e}")
    
    return None

def get_master_classification(ip_address):
    """
    Retrieves the expected classification category for a given IP address
    from the master classification data.
    
    Args:
        ip_address (str): The IP address to lookup
        
    Returns:
        str: The expected category or None if not found
    """
    logger = logging.getLogger(__name__)

    try:
        # Import the master classification data
        from local_descriptions_object import LOCAL_DESCRIPTIONS
        
        # Search for the IP address in the master data
        for entry in LOCAL_DESCRIPTIONS:
            if entry["ip_address"] == ip_address:
                return entry["category"]
        
        # If no match was found
        log_info(logger, f"[INFO] No master classification found for IP {ip_address}")
        return None
        
    except ImportError as e:
        log_error(logger, f"[ERROR] Failed to import master classification data: {e}")
        return None
    except Exception as e:
        log_error(logger, f"[ERROR] Error retrieving master classification: {e}")
        return None


def copy_flows_to_newflows():
    """
    Copy all flows from source databases defined in CONST_TEST_SOURCE_DB to newflows.db
    """
    logger = logging.getLogger(__name__)

    for source_db in CONST_TEST_SOURCE_DB:
        try:
            if not os.path.exists(source_db):
                log_warn(logger, f"[WARN] Database not found: {source_db}")
                continue

            # Connect to source database
            source_conn = connect_to_db(source_db, "flows")
            source_cursor = source_conn.cursor()

            log_info(logger, f"[INFO] Copying flows from {source_db} to {source_db}")       

            # Get all flows from source
            source_cursor.execute("SELECT * FROM flows")
            rows = source_cursor.fetchall()
            
            log_info(logger, f"[INFO] Fetched {len(rows)} rows from {source_db}")
            # Connect to newflows database
            newflows_conn = connect_to_db(CONST_CONSOLIDATED_DB, "newflows")
            newflows_cursor = newflows_conn.cursor()

            log_info(logger, f"[INFO] Preparing to insert flows into {CONST_CONSOLIDATED_DB}")
            # Insert flows into newflows
            for row in rows:
                newflows_cursor.execute('''
                    INSERT INTO newflows (
                        src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, flow_start, flow_end, last_seen, times_seen, tags
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(src_ip, dst_ip, src_port, dst_port, protocol)
                    DO UPDATE SET 
                        packets = packets + excluded.packets,
                        bytes = bytes + excluded.bytes,
                        flow_end = excluded.flow_end,
                        last_seen = excluded.last_seen,
                        times_seen = times_seen + 1
                ''', row)
                
            newflows_conn.commit()
            log_info(logger, f"[INFO] Copied {len(rows)} flows from {source_db}")
            
        except sqlite3.Error as e:
            log_error(logger, f"[ERROR] Database error processing {source_db}: {e}")
        finally:
            if 'source_conn' in locals():
                source_conn.close()
            if 'newflows_conn' in locals():
                newflows_conn.close()

def log_test_results(start_time, end_time, duration, total_rows, filtered_rows, detection_durations, tag_distribution, classification_results):
    """
    Log test execution results to a new JSON file for each test run.

    Args:
        start_time: Test start timestamp
        end_time: Test end timestamp
        duration: Test duration in seconds
        total_rows: Total number of rows processed
        filtered_rows: Number of rows after ignorelist filtering
        detection_durations: Dictionary containing durations for detection functions
    """
    logger = logging.getLogger(__name__)
    try:
        # Get alert categories and counts
        alerts_conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        alerts_cursor = alerts_conn.cursor()
        alerts_cursor.execute("""
            SELECT category, COUNT(*) as count 
            FROM alerts 
            GROUP BY category 
            ORDER BY count DESC
        """)
        categories = {category: count for category, count in alerts_cursor.fetchall()}
        alerts_conn.close()

        # Prepare the test result data
        test_result = {
            "version": VERSION,
            "execution_date": datetime.now().strftime("%Y-%m-%d"),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": round(duration, 2),
            "total_rows": total_rows,
            "filtered_rows": filtered_rows,
            "database_counts": {
                "actions": get_row_count(CONST_CONSOLIDATED_DB, "actions"),
                "alerts": get_row_count(CONST_CONSOLIDATED_DB, 'alerts'),
                "allflows": get_row_count(CONST_CONSOLIDATED_DB, 'allflows'),
                "configuration": get_row_count(CONST_CONSOLIDATED_DB, 'configuration'),
                "customtags": get_row_count(CONST_CONSOLIDATED_DB, "customtags"),           
                "geolocation": get_row_count(CONST_CONSOLIDATED_DB, 'geolocation'),  
                "ignorelist": get_row_count(CONST_CONSOLIDATED_DB, 'ignorelist'),                                             
                "localhosts": get_row_count(CONST_CONSOLIDATED_DB, 'localhosts'),
                "newflows": get_row_count(CONST_CONSOLIDATED_DB, 'newflows'),
                "dnsqueries": get_row_count(CONST_CONSOLIDATED_DB, "dnsqueries"),  
                "reputationlist": get_row_count(CONST_CONSOLIDATED_DB, "reputationlist"),
                "services": get_row_count(CONST_CONSOLIDATED_DB, "services"),
                "tornodes": get_row_count(CONST_CONSOLIDATED_DB, "tornodes"),
                "trafficstats": get_row_count(CONST_CONSOLIDATED_DB, "trafficstats"),
                "ipasn": get_row_count(CONST_CONSOLIDATED_DB, "ipasn")
            },
            "tag_distribution": tag_distribution,
            "alert_categories": categories,
            "detection_durations": detection_durations,
            "classification_results": classification_results
        }

        # Ensure the test_results directory exists
        test_results_dir = Path(__file__).parent / "test_results"
        test_results_dir.mkdir(exist_ok=True)

        # Create a new file for this test run
        filename = f"{start_time.strftime('%Y-%m-%d_%H-%M-%S')}.json"
        results_file = test_results_dir / filename

        # Write the test result to the file in a pretty JSON format
        with open(results_file, 'w') as f:
            json.dump(test_result, f, indent=4)

        log_info(logger, f"[INFO] Test results written to {results_file}")

    except Exception as e:
        log_error(logger, f"[ERROR] Failed to write test results: {e}")

def main():
    """Main function to copy flows from multiple databases"""
    start_time = datetime.now()
    logger = logging.getLogger(__name__)

    SITE = os.getenv("SITE", CONST_SITE)

    site_config_path = os.path.join("/database/", f"{SITE}.py")

    if os.path.exists(CONST_CONSOLIDATED_DB):
        os.remove(CONST_CONSOLIDATED_DB)
        log_info(logger, f"[INFO] Deleted existing consolidated database: {CONST_CONSOLIDATED_DB}")
  
    
    if not os.path.exists(CONST_CONSOLIDATED_DB):
        log_info(logger, f"[INFO] Consolidated database not found, creating at {CONST_CONSOLIDATED_DB}. We assume this is a first time install. ")
        create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_CONFIG_SQL, "configuration")
        log_info(logger, f"[INFO] No site-specific configuration found at {site_config_path}. This is OK. ")
        config_dict = init_configurations_from_variable()
    else:
        log_info(logger, f"[INFO] Consolidated database found at {CONST_CONSOLIDATED_DB}.")

    if os.path.exists(site_config_path):
        log_info(logger, f"[INFO] Loading site-specific configuration from {site_config_path}. Leaving this file will overwrite the config database every time, so be careful. It's usually only meant for a one time bootstrapping of a new site with a full config.")
        delete_all_records(CONST_CONSOLIDATED_DB, "configuration")
        config_dict = init_configurations_from_sitepy()
        create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_IGNORELIST_SQL, "ignorelist")
        create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_CUSTOMTAGS_SQL, "customtags")
        import_ignorelists(config_dict)
        import_custom_tags(config_dict)

    store_machine_unique_identifier()
    store_version()
    store_site_name(SITE)
    config_dict = get_config_settings()

    print(f"Configuration: {config_dict}")
    check_update_database_schema(config_dict)

    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_SERVICES_SQL, "services")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_CONFIG_SQL, "configuration")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_IGNORELIST_SQL, "ignorelist")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_CUSTOMTAGS_SQL, "customtags")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_TRAFFICSTATS_SQL, "trafficstats")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_ALERTS_SQL, "alerts")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_ALLFLOWS_SQL,"allflows")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_NEWFLOWS_SQL, "newflows")
    delete_all_records(CONST_CONSOLIDATED_DB,"newflows")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_LOCALHOSTS_SQL, "localhosts")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_GEOLOCATION_SQL, "geolocation")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_REPUTATIONLIST_SQL, "reputationlist")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_TORNODES_SQL, "tornodes")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_DNSQUERIES_SQL, "dnsqueries")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_ACTIONS_SQL, "actions")
    create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_IPASN_SQL, "ipasn")

    copy_flows_to_newflows()

    conn = connect_to_db(CONST_CONSOLIDATED_DB, "newflows")

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM newflows")
    rows = cursor.fetchall()
    rows = [list(row) for row in rows]

    log_info(logger, f"[INFO] Fetched {len(rows)} rows from {CONST_CONSOLIDATED_DB}")

    ignorelist_entries = get_ignorelist()
    customtag_entries = get_custom_tags()

    LOCAL_NETWORKS = set(config_dict['LocalNetworks'].split(','))

    # Calculate broadcast addresses for all local networks
    broadcast_addresses = set()
    for network in LOCAL_NETWORKS:
        broadcast_ip = calculate_broadcast(network)
        if broadcast_ip:
            broadcast_addresses.add(broadcast_ip)

    broadcast_addresses.add('255.255.255.255')
    broadcast_addresses.add('0.0.0.0')

    # Convert rows to dictionaries for input into apply_tags
    column_names = [desc[0] for desc in cursor.description]  # Get column names from the cursor
    rows_as_dicts = [dict(zip(column_names, row)) for row in rows]

    # Add a 'tags' dictionary value to every row
    for row in rows_as_dicts:
        row['tags'] = ""  # Initialize an empty string for tags

    # Apply tags
    tagged_rows_as_dicts = [apply_tags(row, ignorelist_entries, broadcast_addresses, customtag_entries, config_dict, CONST_LINK_LOCAL_RANGE) for row in rows_as_dicts]

    # Convert back to arrays for use in update_allflows
    tagged_rows = [[row[col] if col in row else None for col in column_names] for row in tagged_rows_as_dicts]

    update_all_flows(tagged_rows, config_dict)
    update_traffic_stats(tagged_rows, config_dict)

    # Dictionary to store durations for each detection function
    detection_durations = {}

    # Run detection functions and calculate durations
    start = datetime.now()
    update_local_hosts(tagged_rows, config_dict)
    detection_durations['update_local_hosts'] = int((datetime.now() - start).total_seconds())


    filtered_rows = [row for row in tagged_rows if 'IgnoreList' not in str(row[11])]
    log_info(logger, f"[INFO] Finished removing IgnoreList flows - processing flow count is {len(filtered_rows)}")

    filtered_rows = [row for row in filtered_rows if 'Broadcast' not in str(row[11])]
    log_info(logger, f"[INFO] Finished removing Broadcast flows - processing flow count is {len(filtered_rows)}")

    filtered_rows = [row for row in filtered_rows if 'Multicast' not in str(row[11])]
    log_info(logger, f"[INFO] Finished removing Multicast flows - processing flow count is {len(filtered_rows)}")

    filtered_rows = [row for row in filtered_rows if 'LinkLocal' not in str(row[11])]
    log_info(logger,f"[INFO] Finished removing LinkLocal flows - processing flow count is {len(filtered_rows)}")

    filtered_rows = tagged_rows

    start = datetime.now()
    detect_new_outbound_connections(filtered_rows, config_dict)
    detection_durations['detect_new_outbound_connections'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    router_flows_detection(filtered_rows, config_dict)
    detection_durations['router_flows_detection'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    foreign_flows_detection(filtered_rows, config_dict)
    detection_durations['foreign_flows_detection'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    local_flows_detection(filtered_rows, config_dict)
    detection_durations['local_flows_detection'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_dead_connections(config_dict)
    detection_durations['detect_dead_connections'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_unauthorized_dns(filtered_rows, config_dict)
    detection_durations['detect_unauthorized_dns'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_unauthorized_ntp(filtered_rows, config_dict)
    detection_durations['detect_unauthorized_ntp'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_incorrect_ntp_stratum(filtered_rows, config_dict)
    detection_durations['detect_incorrect_ntp_stratum'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_incorrect_authoritative_dns(filtered_rows, config_dict)
    detection_durations['detect_incorrect_authoritative_dns'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_vpn_traffic(filtered_rows, config_dict)
    detection_durations['detect_vpn_traffic'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_many_destinations(filtered_rows, config_dict)
    detection_durations['detect_many_destinations'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_high_risk_ports(filtered_rows, config_dict)
    detection_durations['detect_high_risk_ports'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_port_scanning(filtered_rows, config_dict)
    detection_durations['detect_port_scanning'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_many_destinations(filtered_rows, config_dict)
    detection_durations['detect_many_destinations'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    update_tor_nodes(config_dict)
    detect_tor_traffic(filtered_rows, config_dict)
    detection_durations['detect_tor_traffic'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_high_bandwidth_flows(filtered_rows, config_dict)
    detection_durations['detect_high_bandwidth_flows'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    detect_custom_tag(filtered_rows, config_dict)
    detection_durations['detect_custom_tag'] = int((datetime.now() - start).total_seconds())

    log_info(logger, "[INFO] Preparing to detect geolocation flows...")
    start = datetime.now()
    create_geolocation_db()
    geolocation_data = load_geolocation_data()
    detect_geolocation_flows(filtered_rows, config_dict, geolocation_data)
    detection_durations['detect_geolocation_flows'] = int((datetime.now() - start).total_seconds())

    log_info(logger, "[INFO] Preparing to download pihole dns query logs...")
    start = datetime.now()
    get_pihole_ftl_logs(10000,config_dict)
    detection_durations['retrieve_pihole_dns_query_logs'] = int((datetime.now() - start).total_seconds())

    log_info(logger, "[INFO] Preparing to resolve unresolved dns entries...")
    start = datetime.now()
    resolve_empty_dns_responses(config_dict)
    detection_durations['resolve_empty_dns_responses'] = int((datetime.now() - start).total_seconds())

    log_info(logger, "[INFO] Preparing to detect reputation list flows...")
    start = datetime.now()
    import_reputation_list(config_dict)
    reputation_data = load_reputation_data()
    detect_reputation_flows(filtered_rows, config_dict, reputation_data)
    detection_durations['detect_reputationlist_flows'] = int((datetime.now() - start).total_seconds())

    log_info(logger, "[INFO] Preparing to fetch services list...")
    start = datetime.now()
    create_services_db()
    services_data = get_all_services()
    detection_durations['fetch_services_flow'] = int((datetime.now() - start).total_seconds())


    start = datetime.now()
    log_info(logger,"[INFO] Retrieving IP2ASN Database..")
    create_asn_database()
    log_info(logger, "[INFO] IP2ASN update finished.")
    detection_durations['fetch_ip2asn'] = int((datetime.now() - start).total_seconds())



    combined_results = {}
    localhosts = get_localhosts()

    start = datetime.now()
    dns_results = dns_lookup(localhosts, config_dict['ApprovedLocalDnsServersList'].split(','), config_dict)
    log_info(logger,f"[INFO] DNS Results: {json.dumps(dns_results)}")
    for result in dns_results:
        ip = result["ip"]
        combined_results[ip] = {
            "dns_hostname": result.get("dns_hostname", None),
        }
    detection_durations['discovery_dns'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    dl_results = get_pihole_dhcp_leases(localhosts, config_dict)
    log_info(logger,f"[INFO] Pihole DHCP Lease Results: {json.dumps(dl_results)}")
    for result in dl_results:
        ip = result["ip"]
        if ip not in combined_results:
            combined_results[ip] = {}
        combined_results[ip].update({
            "lease_hostname": result.get("lease_hostname", combined_results[ip].get("lease_hostname")),
            "lease_hwaddr": result.get("lease_hwaddr", combined_results[ip].get("lease_hwaddress")),
            "lease_clientid": result.get("lease_clientid", combined_results[ip].get("lease_clientid")),
        })
    detection_durations['discovery_pihole_dhcp_leases'] = int((datetime.now() - start).total_seconds())

    start = datetime.now()
    nd_results = get_pihole_network_devices(localhosts, config_dict)
    log_info(logger,f"[INFO] Pihole Network Device Results: {json.dumps(nd_results)}")
    for result in nd_results:
        ip = result["ip"]
        if ip not in combined_results:
            combined_results[ip] = {}
        combined_results[ip].update({
            "dhcp_hostname": result.get("dhcp_hostname", combined_results[ip].get("dhcp_hostname")),
            "mac_address": result.get("mac_address", combined_results[ip].get("mac_address")),
            "mac_vendor": result.get("mac_vendor", combined_results[ip].get("mac_vendor")),
        })
    detection_durations['discovery_pihole_network_devices'] = int((datetime.now() - start).total_seconds())


    if config_dict.get("DiscoveryNmapOsFingerprint", 0) == 1:
        start = datetime.now()
        # Limit the list of localhosts to the first 3 entries
        sub_localhosts = list(localhosts)[:1]   # Slice the list to include only the first 3 hosts
        nmap_results = os_fingerprint(sub_localhosts, config_dict)

        log_info(logger, f"[INFO] Nmap Results: {json.dumps(nmap_results)}")

        for result in nmap_results:
            ip = result["ip"]
            if ip not in combined_results:
                combined_results[ip] = {}
            combined_results[ip].update({
                "os_fingerprint": result.get("os_fingerprint", combined_results[ip].get("os_fingerprint")),
            })
        detection_durations['discovery_nmap_os_fingerprint'] = int((datetime.now() - start).total_seconds())

    # Query to count rows grouped by tags
    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "allflows")
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*) as count, tags 
            FROM allflows 
            GROUP BY tags;
        """)

        tag_counts = cursor.fetchall()
        conn.close()

        # Prepare the tags_distribution dictionary
        tags_distribution = {tag: count for count, tag in tag_counts}

        log_info(logger, f"[INFO] Tags distribution: {tags_distribution}")

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Failed to fetch tag counts from allflows: {e}")
        tags_distribution = {}


    for ip, data in combined_results.items():
        update_localhosts(
            ip_address=ip,
            mac_address=data.get("mac_address"),
            mac_vendor=data.get("mac_vendor"),
            dhcp_hostname=data.get("dhcp_hostname"),
            dns_hostname=data.get("dns_hostname"),
            os_fingerprint=data.get("os_fingerprint"),
            lease_hostname=data.get("lease_hostname"),
            lease_hwaddr=data.get('lease_hwaddr'),
            lease_clientid=data.get('lease_clientid')
        )

    calculate_update_threat_scores()

    log_info(logger, "\n===== STARTING CLASSIFICATION TEST =====")

    total_clients = 0
    classified_clients = 0
    master_data_matches = 0
    master_data_mismatches = 0
    classification_details = []

    localhosts = get_localhosts()
    for eachip in localhosts:

        total_clients += 1
        client_data = export_client_definition(eachip)
        save_client_data(eachip, client_data)
        
        if client_data:
            print(f"Client data retrieved for {eachip}")
            result = classify_client("TESTPPE", client_data)
            
            if result:
                classified_clients += 1
                
                # Get API classification result
                best_match = result.get("best_match", ["UNKNOWN"])
                api_category = best_match[0] if best_match and isinstance(best_match, (list, tuple)) else "UNKNOWN"
                                
                # Get expected classification from master data
                expected_category = get_master_classification(eachip)
                
                if expected_category:
                    # Compare API result with expected result
                    if api_category == expected_category:
                        master_data_matches += 1
                        match_status = "MATCH ✓"
                    else:
                        master_data_mismatches += 1
                        match_status = "MISMATCH ✗"
                        
                    print(f"Client {eachip}: API: {api_category}, Expected: {expected_category} - {match_status}")
                    
                    # Store the comparison result for summary
                    classification_details.append({
                        "ip": eachip,
                        "api": api_category,
                        "expected": expected_category,
                        "match": api_category == expected_category
                    })
                else:
                    print(f"Client {eachip}: API: {api_category}, No expected classification available")
                    classification_details.append({
                        "ip": eachip,
                        "api": api_category,
                        "expected": "N/A",
                        "match": None
                    })
            else:
                print(f"Failed to classify client {eachip}")
        else:
            print(f"Failed to fetch client data for {eachip}")

    accuracy = 0
    if master_data_matches + master_data_mismatches > 0:
        accuracy = (master_data_matches / (master_data_matches + master_data_mismatches)) * 100

    classification_results= {}
    classification_results["accuracy"] = accuracy
    classification_results["total_clients"] = total_clients
    classification_results["classified_clients"] = classified_clients
    classification_results["master_data_matches"] = master_data_matches
    classification_results["master_data_mismatches"] = master_data_mismatches

    log_info(logger, "[INFO] Processing finished.")
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    log_info(logger, f"[INFO] Total execution time: {duration:.2f} seconds")

    log_test_results(start_time, end_time, duration, len(rows), len(filtered_rows), detection_durations, tags_distribution, classification_results)
   
if __name__ == "__main__":
    main()