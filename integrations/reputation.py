import requests
import sqlite3
import logging
from ipaddress import ip_network
import sys
from pathlib import Path

import os
import sqlite3
import sys
from datetime import datetime, timedelta
from database.reputation import insert_reputation, get_all_reputation_records
from pathlib import Path
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *


def import_reputation_list(config_dict):
    """
    Downloads the reputation list and imports it into the reputationlist table
    in the geolocations.db database.

    Args:
        config_dict (dict): Configuration dictionary.
        excluded_networks (list): A list of networks (in CIDR format) to exclude from the import.
    """

    logger = logging.getLogger(__name__)
    reputation_url = config_dict.get("ReputationUrl", "https://iplists.firehol.org/files/firehol_level1.netset")

    # Default to an empty list if no excluded networks are provided
    excluded_networks = config_dict.get("ReputationListRemove", "").split(",")
    if excluded_networks:
        excluded_networks = [ip_network(net) for net in excluded_networks]

    try:
        # Download the  reputation list
        log_info(logger, f"[INFO] Downloading IP bad reputation list from {reputation_url}")
        response = requests.get(reputation_url, timeout=10)
        response.raise_for_status()
        netset_data = response.text.splitlines()

        # Filter and process the netset data
        processed_networks = []
        for line in netset_data:
            line = line.strip()
            if not line or line.startswith("#"):  # Ignore comments and empty lines
                continue

            try:
                network = ip_network(line)

                # Exclude networks in the excluded list
                if any(network.overlaps(excluded) for excluded in excluded_networks):
                    log_info(logger, f"[INFO] Excluding network: {line}")
                    continue

                # Calculate start_ip, end_ip, and netmask
                start_ip = int(network.network_address)
                end_ip = int(network.broadcast_address)
                netmask = network.prefixlen
                insert_reputation(str(network), start_ip, end_ip, netmask)
                processed_networks.append((str(network), start_ip, end_ip, netmask))
            except ValueError:
                log_error(logger, f"[ERROR] Invalid network entry in reputation list: {line}")

        log_info(logger, f"[INFO] Imported {len(processed_networks)} networks into the reputation table.")
    except requests.exceptions.RequestException as e:
        log_error(logger, f"[ERROR] Failed to download reputation list: {e}")
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error: {e}")
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error: {e}")


def load_reputation_data():
    """
    Load reputation list data from the database into memory.

    Returns:
        list: A list of tuples containing (network, country_name).
    """
    logger = logging.getLogger(__name__)

    geolocation_data = get_all_reputation_records()

    return geolocation_data