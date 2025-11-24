
import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
import time
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
from locallogging import log_info, log_error, log_warn
from notifications.core import handle_alert
from init import *

def update_local_hosts(rows, config_dict):
    """
    Check for new IPs in the provided rows and add them to localhosts.db if necessary.
    Uses an in-memory list to avoid repeated database queries.
    """
    logger = logging.getLogger(__name__)
    log_info(logger,"[INFO] Starting to update local hosts")
    # Connect to the localhosts database
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

    try:

        existing_localhosts = get_localhosts()
        log_info(logger, f"[INFO] Loaded {len(existing_localhosts)} existing local hosts into memory")
    
        for row in rows:
            for range_index in (0, 1):  # Assuming the IP addresses are in the first two columns
                ip_address = row[range_index]

                # Check if the IP is within any of the allowed network ranges
                is_local = is_ip_in_range(ip_address, LOCAL_NETWORKS)

                if is_local and ip_address not in existing_localhosts:
                    # Add the new IP to localhosts.db
                    first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    original_flow = json.dumps(row)  # Encode the original flow as JSON
                    insert_localhost_basic(ip_address, original_flow)

                    existing_localhosts.add(ip_address)  # Add to in-memory set
                    log_info(logger, f"[INFO] Added new IP to localhosts.db: {ip_address}")
                    
                    insert_action(f"New host detected: Assign a description and category for {ip_address}")

                    message = f"New Host Detected: {ip_address}"

                    handle_alert(
                        config_dict,
                        "NewHostsDetection",
                        message,
                        ip_address,
                        row,
                        "New Host Detected",
                        "",
                        "",
                        f"{ip_address}_NewHostsDetection"
                    )  

    except Exception as e:
        log_error(logger, f"[ERROR] Error in update_local_hosts: {e}")


    log_info(logger,"[INFO] Finished updating local hosts")