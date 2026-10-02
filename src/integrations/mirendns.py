import logging
import sqlite3

import requests

from src.database.dnsqueries import insert_dns_query
from src.utils.locallogging import log_error, log_info


def get_miren_dns_logs(seconds, config_dict):
    """
    Fetch and parse DNS query logs from a Miren instance using the /queries API.

    Miren exposes a single global endpoint that returns DNS queries pre-aggregated
    by (client, domain, qtype) for the last ``seconds`` window. Each entry includes
    the client, domain, qtype, a ``count`` of occurrences, and the most recent
    ``last_response``. Only A-record queries are stored, matching the Pi-hole and
    AdGuard integrations, with the response saved alongside the query.

    Args:
        seconds (int): The "last X seconds" window to request from Miren.
        config_dict (dict): Configuration dictionary containing the Miren URL.

    Returns:
        dict: An empty dict (or an error dict) on failure; otherwise returns after
              updating the dnsqueries table.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting Miren dns query log retrieval")

    miren_url = config_dict.get("MirenUrl", None)

    if not miren_url:
        log_error(logger, "[ERROR] Miren URL not provided in configuration")
        return {"error": "Miren URL not provided"}

    endpoint = f"{miren_url}/queries?seconds={seconds}"
    try:
        response = requests.get(endpoint, timeout=10)
        response.raise_for_status()
        data = response.json()
        queries = data.get("queries", [])
    except requests.exceptions.RequestException as e:
        log_error(logger, f"[ERROR] Failed to fetch DNS query logs: {e}")
        return {}
    except Exception as e:
        log_error(logger, f"[ERROR] An unexpected error occurred: {e}")
        return {}

    client_data = {}
    query_count = 0
    for entry in queries:
        query_count += 1
        try:
            domain = entry.get("domain")
            client_ip = entry.get("client")
            if not client_ip or not domain:
                continue
            # Only store A-record lookups, matching the Pi-hole/AdGuard integrations
            if entry.get("qtype") != "A":
                continue
            # Miren pre-aggregates, so "count" is the number of occurrences.
            domains = client_data.setdefault(client_ip, {})
            record = domains.setdefault(domain, {"times_seen": 0, "response": None})
            record["times_seen"] += entry.get("count", 1)
            last_response = entry.get("last_response")
            if last_response:
                record["response"] = last_response
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to process entry: {entry}, Error: {e}")
    log_info(
        logger,
        f"[INFO] Successfully processed DNS query logs for {len(client_data)} clients and {query_count} queries",
    )
    for client_ip, domains in client_data.items():
        for domain, record in domains.items():
            try:
                insert_dns_query(
                    client_ip,
                    domain,
                    record["times_seen"],
                    "miren",
                    response=record["response"],
                )
            except sqlite3.Error as e:
                log_error(
                    logger,
                    f"[ERROR] Failed to update database for client_ip: {client_ip}, domain: {domain}, Error: {e}",
                )
    log_info(logger, "[INFO] Successfully updated dns query history")
