import requests
import logging
import sys
import time
import sqlite3
from pathlib import Path

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


def authenticate_pihole(pihole_url, api_token):
    """
    Authenticate with the Pi-hole v6 API and retrieve a session ID.

    Args:
        pihole_url (str): The base URL of the Pi-hole instance (e.g., "http://192.168.1.2/admin").
        api_token (str): The API token for authenticating with the Pi-hole API.

    Returns:
        str: The session ID if authentication is successful, or None if it fails.
    """
    logger = logging.getLogger(__name__)

    endpoint = f"{pihole_url}/auth"
    payload = {"password": api_token}  # Send the password in the request body

    try:
        response = requests.post(endpoint, json=payload, timeout=10)  # Use JSON payload
        response.raise_for_status()
        data = response.json()

        # Extract the session ID from the response
        session_data = data.get("session", {})
        if session_data.get("valid", False):
            session_id = session_data.get("sid")
            log_info(logger, f"[INFO] Pihole Authentication successful.")
            return session_id
        else:
            log_error(logger, "[ERROR] Pihole Authentication failed: Invalid credentials")
            return None
    except requests.exceptions.RequestException as e:
        log_error(logger, f"[ERROR] Pihole Authentication failed: {e}")
        return None
    except ValueError:
        log_error(logger, f"[ERROR] Pihole Failed to parse authentication response")
        return None


def get_pihole_ftl_logs(page_size, config_dict):
    """
    Fetch and parse DNS query logs from a Pi-hole v6 instance using the /queries API.
    Create a data object for each client_ip that includes the domains it queried
    and a count of the number of times that client_ip/domain pair was seen in the data.
    Update the pihole table in the dnsqueries.db database with the parsed data.
    On insert, set first_seen, last_seen, and times_seen to 1 by default.
    If the record already exists, update last_seen and increment times_seen.

    Args:
        config_dict (dict): Configuration dictionary containing Pi-hole URL and API token.

    Returns:
        dict: A dictionary containing client_ip as keys and their queried domains with counts as values,
              along with metadata about the query logs.
    """
    logger = logging.getLogger(__name__)

    log_info(logger, "[INFO] Starting Pi-hole dns query log retrieval")

    pihole_url = config_dict.get('PiholeUrl', None)
    api_token = config_dict.get('PiholeApiKey', None)
    fetch_interval = config_dict.get('IntegrationFetchInterval', 3660)

    if not pihole_url or not api_token:
        log_error(logger, "[ERROR] Pi-hole URL or API token not provided in configuration")
        return {"error": "Pi-hole URL or API token not provided"}

    session_id = authenticate_pihole(pihole_url, api_token)
    if not session_id:
        log_error(logger, "[ERROR] Pi-hole Authentication failed. Exiting.")
        return {}

    current_epoch = int(time.time())
    start_epoch = current_epoch - fetch_interval

    endpoint = f"{pihole_url}/queries?length={page_size}&from={start_epoch}&until={current_epoch}"
    headers = {"sid": f"{session_id}"}

    try:

        # Fetch data from Pi-hole
        response = requests.get(endpoint, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        log_info(logger, "[INFO] Received response from Pi-hole")

        # Extract the queries array and metadata
        queries = data.get("queries", [])
        metadata = {
            "cursor": data.get("cursor"),
            "recordsTotal": data.get("recordsTotal"),
            "recordsFiltered": data.get("recordsFiltered"),
            "draw": data.get("draw"),
            "took": data.get("took")
        }

        # Parse the JSON objects and create the client_ip data object
        client_data = {}
        query_count = 0

        for entry in queries:
            query_count += 1
            try:
                # Only process entries where type = "A"
                if entry.get("type") != "A":
                    continue

                client_ip = entry.get("client", {}).get("ip")
                domain = entry.get("domain")

                if not client_ip or not domain:
                    continue

                # Initialize client_ip in client_data if not already present
                if client_ip not in client_data:
                    client_data[client_ip] = {}

                # Increment the count for the client_ip/domain pair
                if domain not in client_data[client_ip]:
                    client_data[client_ip][domain] = 0
                client_data[client_ip][domain] += 1

            except Exception as e:
                log_error(logger, f"[ERROR] Failed to process entry: {entry}, Error: {e}")

        log_info(logger, f"[INFO] Successfully processed DNS query logs for {len(client_data)} clients and {query_count} queries")

        # Update the pihole table in the database
        for client_ip, domains in client_data.items():
            for domain, times_seen in domains.items():
                try:
                    insert_dns_query(client_ip, domain, times_seen, "pihole")
                except sqlite3.Error as e:
                    log_error(logger, f"[ERROR] Failed to update database for client_ip: {client_ip}, domain: {domain}, Error: {e}")

        log_info(logger, "[INFO] Successfully updated dns query history")


    except requests.exceptions.RequestException as e:
        log_error(logger, f"[ERROR] Failed to fetch DNS query logs: {e}")
        return {}
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error: {e}")
        return {}
    except Exception as e:
        log_error(logger, f"[ERROR] An unexpected error occurred: {e}")
        return {}
