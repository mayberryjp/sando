import requests  # Add this import
import sqlite3
import csv
import os
import logging
import zipfile
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
from database.geolocation import insert_geolocation, get_all_geolocations, get_country_by_ip_int
sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *


if IS_CONTAINER:
    SITE = os.getenv("SITE", CONST_SITE)

def create_geolocation_db():
    """
    Fetches the MaxMind GeoLite2 database from their API, extracts the CSV files, and creates a SQLite database.
    Falls back to using local copies if the download fails.
    Also adds LOCAL_NETWORKS with SITE_NAME as country.
    """
    logger = logging.getLogger(__name__)

    config_dict = get_config_settings()
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

    api_key = config_dict.get('MaxMindAPIKey', None)

    # Remove trailing commas to avoid creating tuples
    blocks_csv_url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key={api_key}&suffix=zip"
    locations_csv_url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key={api_key}&suffix=zip"

    temp_dir = "/database"
    BATCH_SIZE = 1000  # Number of records to process in each batch
    
    # Define paths for files
    blocks_zip_path = os.path.join(temp_dir, "GeoLite2-Country-Blocks.zip")
    locations_zip_path = os.path.join(temp_dir, "GeoLite2-Country-Locations.zip")
    blocks_csv_path = os.path.join(temp_dir, "GeoLite2-Country-Blocks-IPv4.csv")
    locations_csv_path = os.path.join(temp_dir, "GeoLite2-Country-Locations-en.csv")

    download_successful = True  # Flag to track if download was successful

    try:
        # Step 1: Create temporary directory if it doesn't exist
        os.makedirs(temp_dir, exist_ok=True)

        # Step 2: Try to download and extract the GeoLite2 database
        log_info(logger, "[INFO] Attempting to download GeoLite2 database from MaxMind...")
        
        try:
            # Download blocks CSV
            blocks_response = requests.get(blocks_csv_url.format(api_key=api_key), stream=True, timeout=30)
            locations_response = requests.get(locations_csv_url.format(api_key=api_key), stream=True, timeout=30)

            if blocks_response.status_code != 200 or locations_response.status_code != 200:
                download_successful = False
                log_warn(logger, "[WARN] Failed to download geolocation data. Will attempt to use local files.")
            else:
                # Save downloaded files
                with open(blocks_zip_path, "wb") as f:
                    f.write(blocks_response.content)
                with open(locations_zip_path, "wb") as f:
                    f.write(locations_response.content)
                
                log_info(logger, "[INFO] Downloaded geolocation data successfully.")
        
        except Exception as e:
            download_successful = False
            log_warn(logger, f"[WARN] Error during download: {e}. Will attempt to use local files.")
        
        # Extract files if download was successful
        if download_successful:
            log_info(logger, "[INFO] Extracting downloaded ZIP files...")
            
            # Function to extract ZIP files with flattened structure
            def extract_flat(zip_file_path, destination_dir):
                with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                    for file_info in zip_ref.infolist():
                        # Skip directories
                        if file_info.filename[-1] == '/':
                            continue

                        # Get just the base filename without path
                        base_filename = os.path.basename(file_info.filename)

                        # Skip if no filename (just a directory)
                        if not base_filename:
                            continue

                        # Extract the file data
                        file_data = zip_ref.read(file_info.filename)

                        # Write to destination directory with just the base filename
                        target_path = os.path.join(destination_dir, base_filename)
                        with open(target_path, 'wb') as target_file:
                            target_file.write(file_data)

            # Extract each ZIP file with flattened structure
            extract_flat(blocks_zip_path, temp_dir)
            extract_flat(locations_zip_path, temp_dir)

        # Check if the required CSV files exist (either from download or already locally)
        if not os.path.exists(blocks_csv_path) or not os.path.exists(locations_csv_path):
            log_error(logger, "[ERROR] Required CSV files not found. Cannot create geolocation database.")
            return

        log_info(logger, f"[INFO] Using geolocation data files: {blocks_csv_path} and {locations_csv_path}")

        # Step 3: Load the country locations data into a dictionary
        log_info(logger, "[INFO] Loading country locations data...")
        locations = {}
        with open(locations_csv_path, "r", encoding="utf-8") as locations_file:
            reader = csv.DictReader(locations_file)
            for row in reader:
                geoname_id = row["geoname_id"]
                country_name = row.get("country_name", "")
                locations[geoname_id] = country_name

        # Step 4: Populate the database from the country blocks CSV file in batches
        log_info(logger, f"[INFO] Populating the SQLite database with country blocks data...")
        geolocation_batch = []
        total_records = 0
        
        with open(blocks_csv_path, "r", encoding="utf-8") as blocks_file:
            reader = csv.DictReader(blocks_file)
            for row in reader:
                network = row["network"]
                start_ip, end_ip, netmask = ip_network_to_range(network)
                if start_ip is None:
                    continue

                geoname_id = row.get("geoname_id")
                country_name = locations.get(geoname_id, None)  # Get the country name from the locations dictionary

                # Add to batch
                geolocation_batch.append((network, start_ip, end_ip, netmask, country_name))
                
                # When batch size is reached, process the batch
                if len(geolocation_batch) >= BATCH_SIZE:
                    success_count, _ = insert_geolocation(geolocation_batch)
                    total_records += success_count
                    geolocation_batch = []  # Clear the batch
                    log_info(logger, f"[INFO] Inserted {total_records} geolocation records so far...")

        # Process any remaining records in the last batch
        if geolocation_batch:
            success_count, _ = insert_geolocation(geolocation_batch)
            total_records += success_count
            log_info(logger, f"[INFO] Inserted {total_records} total MaxMind geolocation records")
            geolocation_batch = []  # Clear the batch

        # After processing CSV files, add LOCAL_NETWORKS
        log_info(logger, f"[INFO] Adding LOCAL_NETWORKS to geolocation database...")
        local_networks_batch = []

        # Handle OtherNetworks from config_dict (format: AZURE=192.168.60.0/24,FARM=192.168.230.0/24)
        other_networks_str = config_dict.get("OtherNetworks", "")
        other_networks_set = set()
        if other_networks_str:
            for pair in other_networks_str.split(","):
                if "=" in pair:
                    site_name, network = pair.split("=", 1)
                    site_name = site_name.strip()
                    network = network.strip()
                    start_ip, end_ip, netmask = ip_network_to_range(network)
                    if start_ip is not None:
                        local_networks_batch.append((network, start_ip, end_ip, netmask, site_name))
                        other_networks_set.add(network)

        for network in LOCAL_NETWORKS:
            if network in other_networks_set:
                continue  # Skip if already in other_networks
            start_ip, end_ip, netmask = ip_network_to_range(network)
            if start_ip is None:
                continue
            local_networks_batch.append((network, start_ip, end_ip, netmask, SITE))

        log_info(logger, f"[INFO] Adding Other Networks to geolocation database...")

        # Process the local networks batch
        if local_networks_batch:
            success_count, _ = insert_geolocation(local_networks_batch)
            log_info(logger, f"[INFO] Added {success_count} local and other network records to geolocation database")

        log_info(logger, f"[INFO] Geolocation database {CONST_CONSOLIDATED_DB} created successfully.")

    except Exception as e:
        log_error(logger, f"[ERROR] Error creating geolocation database: {e}")

def load_geolocation_data():
    """
    Load geolocation data from the database into memory.

    Returns:
        list: A list of tuples containing (network, country_name).
    """
    logger = logging.getLogger(__name__)
    geolocation_data = []

    geolocation_data = get_all_geolocations()
    return geolocation_data

def lookup_ip_country(ip_address):
    """
    Look up the country for a given IP address by converting it to an integer
    and finding which geolocation range it falls within.
    
    Args:
        ip_address (str): The IP address to look up
        
    Returns:
        str: The country name, or None if not found
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Convert IP address to integer using the utility function
        ip_int = ip_to_int(ip_address)
        
        if ip_int is None:
            log_error(logger, f"[ERROR] Invalid IP address format: {ip_address}")
            return None
        
        result = get_country_by_ip_int(ip_int)

        if result:
            return result
        else:
            log_info(logger, f"[INFO] No country found for IP address: {ip_address}")
            return None
            
            
    except Exception as e:
        log_error(logger, f"[ERROR] Error looking up country for IP {ip_address}: {e}")
        return None


