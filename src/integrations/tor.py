import logging

import requests

from src.database.core import delete_all_records
from src.database.tornodes import insert_tor_node
from src.utils.locallogging import log_error, log_info


def update_tor_nodes(config_dict):
    """
    Download and update Tor node list from dan.me.uk.
    Deletes all existing entries in the tornodes table before updating.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting tor node processing")

    tor_nodes_url = config_dict.get(
        "TorNodesUrl", "https://www.dan.me.uk/torlist/?full"
    )

    try:

        # Use delete_all_records to clear the tornodes table
        delete_all_records("tornodes")

        log_info(logger, "[INFO] About to request tor node list from dan.me.uk")
        # Download new list with timeout
        response = requests.get(
            tor_nodes_url,
            headers={
                "User-Agent": "SANDO TorNode Checker (https://www.reddit.com/r/SandoSecurityAndDhcp/"
            },
            timeout=30,  # 30 second timeout
        )
        if response.status_code != 200:
            log_error(
                logger,
                f"[ERROR] Failed to download Tor node list: {response.status_code}",
            )
            return
        log_info(logger, "[INFO] Successfully downloaded Tor node list")
        # Parse IPs (one per line)
        tor_nodes = set(ip.strip() for ip in response.text.split("\n") if ip.strip())

        for ip in tor_nodes:
            insert_tor_node(ip)

        log_info(logger, f"[INFO] Updated Tor node list with {len(tor_nodes)} nodes")

    except Exception as e:
        log_error(logger, f"[ERROR] Error updating Tor nodes: {e}")

    log_info(logger, "[INFO] Finished tor node processing")
