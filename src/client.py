import json
import sqlite3
from pathlib import Path
from enum import Enum
import logging
from datetime import datetime
import requests
from init import *

class ActionType(Enum):
    """Placeholder for action types"""
    pass

def export_client_definition(client_ip):
    """
    Export client information to JSON format.
    Includes:
    - Host information
    - DNS query history with counts
    - Flow statistics with aggregated bytes/packets
    
    Args:
        client_ip (str): IP address of the client
    """
    logger = logging.getLogger(__name__)
    
    try:
        client_data = {
            "ip_address": client_ip,
            "export_date": datetime.now().isoformat(),
            "instance_identifier": get_machine_unique_identifier_from_db(),
            "host_info": None,
            "dns_queries": [],
            "flows": [],
            "actions": []
        }
        
        # Get host information from localhosts.db
        host_record = get_localhost_by_ip(client_ip)
       
        if host_record:
            client_data["host_info"] = {
                "ip_address": host_record[0],
                "mac_address": host_record[3],
                "mac_vendor": host_record[4],
                "dhcp_hostname": host_record[5],
                "dns_hostname": host_record[6],
                "os_fingerprint": host_record[7],
                "lease_hostname": host_record[8],
                "icon": host_record[13],
                "local_description": host_record[12]
            }
        
        dns_rows = get_client_dns_queries(client_ip)
        
        client_data["dns_queries"] = [
            {
                "domain": row[0],
                "times_queried": row[1],
                "first_query": row[2],
                "last_query": row[3]
            }
            for row in dns_rows
        ]
        
        flows_rows = get_flows_by_source_ip(client_ip)
     

        client_data["flows"] = [
            {
                "destination": row[0],
                "port": row[1],
                "protocol": row[2],
                "flow_count": row[3],
                "total_packets": row[4],
                "total_bytes": row[5],
                "last_seen": row[6],
                "first_seen": row[7]
            }
            for row in flows_rows
        ]
        
        return client_data
        
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to export client definition for {client_ip}: {e}")
        return None

def upload_client_definition(ip_address, client_data, machine_id):
    """
    Upload a single client definition to the classification API.
    
    Args:
        ip_address (str): IP address of the client
        client_data (dict): Client definition data to upload
        machine_id (str): Unique identifier for this machine
        
    Returns:
        bool: True if upload successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Construct API endpoint URL
        api_url = f"http://api.homelabids.com:8045/api/classification/{machine_id}/{ip_address}"
        
        # Upload client definition
        response = requests.put(
            api_url,
            json=client_data,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'NetFlowIPS-Client/1.0'
            },
            timeout=30
        )
        
        if response.status_code in (200, 201, 204):
            #log_info(logger, f"[INFO] Successfully uploaded client definition for {ip_address}")
            return True
        else:
            #log_error(logger, f"[ERROR] Failed to upload {ip_address}: HTTP {response.status_code}")
            return False
            
    except requests.RequestException as e:
        log_error(logger, f"[ERROR] Request failed for {ip_address}: {str(e)}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Processing failed for {ip_address}: {str(e)}")
        return False

def upload_all_client_definitions():
    """Get all IP addresses and upload client definitions"""
    logger = logging.getLogger(__name__)
    machine_id = get_machine_unique_identifier_from_db()
    
    try:
        # Get IPs as a set from get_localhosts()
        ip_addresses = get_localhosts()  
        success_count = 0
        error_count = 0
        
        # Debug log to verify data structure
        log_info(logger, f"[DEBUG] Number of IP addresses to process: {len(ip_addresses)}")
        
        for ip_address in ip_addresses:
            time.sleep(3) 
            try:
                client_data = export_client_definition(ip_address)
                
                if not client_data:
                    log_warn(logger, f"[WARN] No client data generated for {ip_address}")
                    continue
                
                if upload_client_definition(ip_address, client_data, machine_id):
                    success_count += 1
                else:
                    error_count += 1
                    
            except Exception as e:
                error_count += 1
                #log_error(logger, f"[ERROR] Processing failed for {ip_address}: {str(e)}")
                
        log_info(logger, f"[INFO] Upload complete. Success: {success_count}, Errors: {error_count}")
        
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error: {str(e)}")


def upload_configuration():
    """
    Retrieve the configuration using get_config_settings and post it as JSON
    to /api/configurations/<instance_identifier>, with sensitive keys removed.
    """
    logger = logging.getLogger(__name__)
    try:
        # Get the instance identifier
        instance_identifier = get_machine_unique_identifier_from_db()

        # Retrieve the configuration
        config_dict = get_config_settings()
        if not config_dict:
            log_error(logger, "[ERROR] Failed to retrieve configuration settings.")
            return False

        # Create a sanitized copy of the configuration
        sanitized_config = config_dict.copy()
        
        # List of sensitive keys to sanitize
        sensitive_keys = [
            "MaxMindAPIKey", 
            "PiholeApiKey", 
            "TelegramBotToken", 
            "TelegramChatId"
        ]
        
        # Set sensitive values to empty strings
        for key in sensitive_keys:
            if key in sanitized_config:
                sanitized_config[key] = ""
                log_info(logger, f"[INFO] Sanitized sensitive key: {key}")

        # Construct the API endpoint URL
        api_url = f"http://api.homelabids.com:8045/api/configurations/{instance_identifier}"

        # Post the sanitized configuration as JSON
        response = requests.post(
            api_url,
            json=sanitized_config,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'NetFlowIPS-Client/1.0'
            },
            timeout=30
        )

        # Check the response status
        if response.status_code in (200, 201, 204):
            log_info(logger, f"[INFO] Successfully uploaded configuration for instance {instance_identifier}.")
            return True
        else:
            log_error(logger, f"[ERROR] Failed to upload configuration: HTTP {response.status_code}")
            return False

    except requests.RequestException as e:
        log_error(logger, f"[ERROR] Request failed while uploading configuration: {str(e)}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while uploading configuration: {str(e)}")
        return False
    
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

def upload_database_metrics():
    """
    Gather database metrics and upload them to the metrics API endpoint.
    Uses the same request sending, logging, and error catching patterns as upload_configuration.
    """
    logger = logging.getLogger(__name__)

    try:
        # Get database file sizes
        explore_db_size = os.path.getsize(CONST_EXPLORE_DB) if os.path.exists(CONST_EXPLORE_DB) else 0
        performance_db_size = os.path.getsize(CONST_PERFORMANCE_DB) if os.path.exists(CONST_PERFORMANCE_DB) else 0

        test_result = {
            "db_schema_version": CONST_DATABASE_SCHEMA_VERSION,
            "machine_unique_identifier": get_machine_unique_identifier_from_db(),
            "site_name": os.getenv("SITE", CONST_SITE),
            "execution_date": datetime.now().strftime("%Y-%m-%d"),
            "database_sizes": {
                "explore_db_size": explore_db_size,
                "performance_db_size": performance_db_size
            },
            "database_counts": {
                "actions": get_row_count("actions"),
                "alerts": get_row_count('alerts'),
                "allflows": get_row_count('allflows'),
                "configuration": get_row_count('configuration'),
                "customtags": get_row_count("customtags"),
                "geolocation": get_row_count('geolocation'),
                "ignorelist": get_row_count('ignorelist'),
                "localhosts": get_row_count('localhosts'),
                "newflows": get_row_count('newflows'),
                "dnsqueries": get_row_count("dnsqueries"),
                "reputationlist": get_row_count("reputationlist"),
                "services": get_row_count("services"),
                "tornodes": get_row_count("tornodes"),
                "trafficstats": get_row_count("trafficstats"),
                "ipasn": get_row_count("ipasn"),
                "explore": get_row_count("explore"),
                "dnskeyvalue": get_row_count("dnskeyvalue"),
                "dbperformance": get_row_count("dbperformance")
            },
            "query_execution_times": get_p95_execution_times()
        }

        # Construct the API endpoint URL
        instance_identifier = test_result["machine_unique_identifier"]
        api_url = f"http://api.homelabids.com:8045/api/database/{instance_identifier}"

        # Post the metrics as JSON
        response = requests.post(
            api_url,
            json=test_result,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'NetFlowIPS-Client/1.0'
            },
            timeout=30
        )

        # Check the response status
        if response.status_code in (200, 201, 204):
            log_info(logger, f"[INFO] Successfully uploaded database metrics for instance {instance_identifier}.")
            return True
        else:
            log_error(logger, f"[ERROR] Failed to upload database metrics: HTTP {response.status_code}")
            return False

    except requests.RequestException as e:
        log_error(logger, f"[ERROR] Request failed while uploading database metrics: {str(e)}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while uploading database metrics: {str(e)}")
        return False
