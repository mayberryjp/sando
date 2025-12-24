import logging
import sqlite3
import time

import requests

from src.database.dnsqueries import insert_dns_query
from src.utils.locallogging import log_error, log_info

def authenticate_adguard(adguard_url, username, password):
    """
    Authenticate with the AdGuard Home API and retrieve a session token (if required).
    Args:
        adguard_url (str): The base URL of the AdGuard Home instance (e.g., "http://192.168.1.3:3000").
        username (str): The username for AdGuard Home.
        password (str): The password for AdGuard Home.
    Returns:
        requests.Session: An authenticated session object, or None if authentication fails.
    """
    logger = logging.getLogger(__name__)
    session = requests.Session()
    try:
        endpoint = f"{adguard_url}/control/login"
        payload = {"name": username, "password": password}
        response = session.post(endpoint, json=payload, timeout=10)
        response.raise_for_status()
        # AdGuard Home returns 200 OK and sets a session cookie if successful
        if response.status_code == 200 and session.cookies:
            log_info(logger, "[INFO] AdGuard authentication successful (session cookie set).")
            return session
        else:
            log_error(logger, "[ERROR] AdGuard authentication failed: No session cookie or bad status code.")
            return None
    except requests.exceptions.RequestException as e:
        log_error(logger, f"[ERROR] AdGuard authentication failed: {e}")
        return None
    except ValueError:
        log_error(logger, "[ERROR] AdGuard failed to parse authentication response")
        return None

def get_adguard_dns_logs(page_size, config_dict):
    """
    Fetch and parse DNS query logs from an AdGuard Home instance using the /control/querylog API.
    Fetches only up to the configured limit (DNS Fetch Record Size).
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting AdGuard dns query log retrieval")

    adguard_url = config_dict.get("AdGuardUrl", None)
    username = config_dict.get("AdGuardUsername", None)
    password = config_dict.get("AdGuardPassword", None)
    fetch_interval = config_dict.get("IntegrationFetchInterval", 3660)

    if not adguard_url or not username or not password:
        log_error(
            logger, "[ERROR] AdGuard URL, username, or password not provided in configuration"
        )
        return {"error": "AdGuard URL, username, or password not provided"}

    session = authenticate_adguard(adguard_url, username, password)
    if not session:
        log_error(logger, "[ERROR] AdGuard authentication failed. Exiting.")
        return {}

    current_epoch = int(time.time())
    start_epoch = current_epoch - fetch_interval

    # Use time_from, time_to, and question_type=A for server-side filtering
    endpoint = f"{adguard_url}/control/querylog?limit={page_size}&time_from={start_epoch}&time_to={current_epoch}&question_type=A"
    try:
        response = session.get(endpoint, timeout=10)
        response.raise_for_status()
        data = response.json()
        queries = data.get("data", [])
    except requests.exceptions.RequestException as e:
        log_error(logger, f"[ERROR] Failed to fetch DNS query logs: {e}")
        return {}
    except Exception as e:
        log_error(logger, f"[ERROR] An unexpected error occurred: {e}")
        return {}

    # No need to check qtype in Python, as the API does it
    client_data = {}
    query_count = 0
    for entry in queries:
        query_count += 1
        try:
            question = entry.get("question", {})
            domain = question.get("name")
            client_ip = entry.get("client")
            if not client_ip or not domain:
                continue
            has_a_answer = any(ans.get("type") == "A" for ans in entry.get("answer", []))
            if not has_a_answer:
                continue
            if client_ip not in client_data:
                client_data[client_ip] = {}
            if domain not in client_data[client_ip]:
                client_data[client_ip][domain] = 0
            client_data[client_ip][domain] += 1
        except Exception as e:
            log_error(
                logger, f"[ERROR] Failed to process entry: {entry}, Error: {e}"
            )
    log_info(
        logger,
        f"[INFO] Successfully processed DNS query logs for {len(client_data)} clients and {query_count} queries",
    )
    for client_ip, domains in client_data.items():
        for domain, times_seen in domains.items():
            try:
                insert_dns_query(client_ip, domain, times_seen, "adguard")
            except sqlite3.Error as e:
                log_error(
                    logger,
                    f"[ERROR] Failed to update database for client_ip: {client_ip}, domain: {domain}, Error: {e}",
                )
    log_info(logger, "[INFO] Successfully updated dns query history")
