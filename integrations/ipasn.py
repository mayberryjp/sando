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
import logging
import requests
import zipfile
import json
import sqlite3
from init import *


def create_asn_database():
    """
    Downloads ASN (Autonomous System Number) data from oxl.app,
    extracts IP ranges and ISP information, and stores it in a database.
    
    This enables IP to ISP lookups to identify the provider of an IP address.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Step 1: Create temporary directory if it doesn't exist
        temp_dir = "/database"
        os.makedirs(temp_dir, exist_ok=True)
        zip_path = os.path.join(temp_dir, "asn_ipv4_full.json.zip")
        json_path = os.path.join(temp_dir, "asn_ipv4_full.json")
        
        # Step 2: Download the ASN data file with 30-second timeout
        log_info(logger, "[INFO] Downloading ASN database from oxl.app with 30 second timeout...")
        try:
            response = requests.get("https://geoip.oxl.app/file/asn_ipv4_full.json.zip", stream=True, timeout=30)
        except requests.exceptions.Timeout:
            log_error(logger, "[ERROR] Timeout after 30 seconds while downloading ASN database.")
            return
        except requests.exceptions.ConnectionError:
            log_error(logger, "[ERROR] Connection error while downloading ASN database. Check your internet connection.")
            return
        
        if response.status_code != 200:
            log_error(logger, f"[ERROR] Failed to download ASN database: {response.status_code}")
            return
            
        with open(zip_path, "wb") as f:
            f.write(response.content)
        
        # Step 3: Extract the ZIP file
        log_info(logger, "[INFO] Extracting ASN database ZIP file...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Step 4: Ensure we have the extracted JSON file
        if not os.path.exists(json_path):
            log_error(logger, "[ERROR] ASN JSON file not found after extraction")
            return
        
        # Step 6: Parse the JSON and insert data into database
        log_info(logger, "[INFO] Processing ASN data and inserting into database...")

        try:
            # For large files, process the data
            count = 0
            with open(json_path, 'r') as json_file:
                data = json.load(json_file)
                
                # New JSON structure is a dictionary with ASNs as keys
                if not isinstance(data, dict):
                    log_error(logger, f"[ERROR] Expected a dictionary of ASN entries, got {type(data).__name__}")
                    return
                    
                total_entries = sum(len(asn_data.get("ipv4", [])) for asn_data in data.values())
                log_info(logger, f"[INFO] Found ASN data for {len(data)} ASNs with approximately {total_entries} network entries")
                
                # Process in batches for better performance
                batch_size = 1000
                current_batch = []
                
                # Loop through each ASN entry
                for asn, asn_data in data.items():
                    # Skip if not a dictionary
                    if not isinstance(asn_data, dict):
                        log_warn(logger, f"[WARN] Skipping invalid ASN data for {asn}")
                        continue
                    
                    # Get IPv4 networks
                    ipv4_networks = asn_data.get("ipv4", [])
                    if not ipv4_networks:
                        continue
                    
                    # Get organization info
                    org_info = asn_data.get("organization", {})
                    org_name = org_info.get("name", "") if isinstance(org_info, dict) else ""
                    
                    # Process each network for this ASN
                    for network in ipv4_networks:
                        # Convert network CIDR to start_ip, end_ip, netmask
                        start_ip, end_ip, netmask = ip_network_to_range(network)
                        if start_ip is None:
                            continue
                        
                        # Add to current batch
                        current_batch.append((
                            network,
                            start_ip,
                            end_ip,
                            netmask,
                            str(asn),
                            org_name
                        ))
                        
                        # Execute batch when it reaches the desired size
                        if len(current_batch) >= batch_size:
                            from database.ipasn import insert_asn_records_batch
                            success, inserted = insert_asn_records_batch(current_batch)
                            if success:
                                count += inserted
                            current_batch = []
                
                # Insert any remaining entries in the last batch
                if current_batch:
                    from database.ipasn import insert_asn_records_batch
                    success, inserted = insert_asn_records_batch(current_batch)
                    if success:
                        count += inserted
                        
        except json.JSONDecodeError as e:
            log_error(logger, f"[ERROR] Invalid JSON format in ASN data file: {e}")
            return

        log_info(logger, f"[INFO] ASN database created successfully with {count} entries")
        
        # Step 8: Clean up temporary files
        if os.path.exists(zip_path):
            os.remove(zip_path)
        if os.path.exists(json_path):
            os.remove(json_path)
            
    except Exception as e:
        log_error(logger, f"[ERROR] Error creating ASN database: {e}")


