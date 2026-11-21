import ipaddress
import json
import logging
import math
import sqlite3
from typing import Optional

from src.database.configuration import get_config_settings, get_local_networks, get_routers
from src.database.core import connect_to_db, disconnect_from_db
from src.utils.locallogging import log_error, log_info, log_warn

_UNSET = object()


def add_connected_network_details(hosts):
    """Enrich host dictionaries from the most specific configured subnet."""
    if not hosts:
        return

    config = get_config_settings()
    if config is None:
        raise sqlite3.OperationalError("Unable to read network configuration")

    networks = []
    for scope in get_local_networks(config, strict=True):
        network = ipaddress.ip_network(scope["cidr"], strict=False)
        interface_name = scope.get("firewall_interface_name")
        if interface_name is not None and not isinstance(interface_name, str):
            raise ValueError("firewall_interface_name must be a string or null")
        networks.append((network, scope["cidr"], interface_name))
    networks.sort(key=lambda entry: entry[0].prefixlen, reverse=True)

    for host in hosts:
        host["connected_interface_name"] = None
        host["connected_network"] = None
        if not host.get("ip_address"):
            continue
        address = ipaddress.ip_address(host["ip_address"])
        for network, cidr, interface_name in networks:
            if address in network:
                host["connected_interface_name"] = (
                    interface_name.lower() if interface_name else None
                )
                host["connected_network"] = cidr
                break


def get_docker_hosts():
    """Return inventory devices eligible to host Docker containers."""
    conn = connect_to_db("localhosts")
    if conn is None:
        raise sqlite3.OperationalError("Unable to connect to localhosts database")
    try:
        cursor = conn.execute(
            """
            SELECT ip_address, local_description, icon
            FROM localhosts
            WHERE icon IN ('LINUX_SERVER', 'WINDOWS_SERVER')
            ORDER BY ip_address
            """
        )
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        disconnect_from_db(conn)


def get_available_ip_address(network: ipaddress.IPv4Network) -> Optional[str]:
    """Return the lowest IPv4 host absent from inventory and configured routers.

    This is a read-only suggestion, not a reservation. Database/configuration
    failures propagate so they cannot be mistaken for an empty inventory.
    """
    config = get_config_settings()
    if config is None:
        raise sqlite3.OperationalError("Unable to read network configuration")

    raw_networks = config.get("LocalNetworks", "[]")
    scopes = json.loads(raw_networks)
    if not isinstance(scopes, list) or any(
        not isinstance(scope, dict)
        or (scope.get("router") is not None and not isinstance(scope["router"], str))
        for scope in scopes
    ):
        raise ValueError("Invalid LocalNetworks configuration")

    unavailable = get_routers({"LocalNetworks": raw_networks})
    conn = connect_to_db("localhosts")
    if conn is None:
        raise sqlite3.OperationalError("Unable to connect to localhosts database")

    try:
        unavailable.update(
            row[0] for row in conn.execute("SELECT ip_address FROM localhosts")
        )
    finally:
        disconnect_from_db(conn)

    # Iterate lazily: even a large subnet stops at the first available host.
    for candidate in network.hosts():
        address = str(candidate)
        if address not in unavailable:
            return address
    return None


def get_localhost_by_ip(ip_address):
    """
    Retrieve complete details for a specific localhost record by IP address.

    Args:
        ip_address (str): The IP address of the localhost to retrieve.

    Returns:
        dict: A dictionary containing all columns for the specified localhost,
              or None if the localhost is not found or an error occurs.
    """
    logger = logging.getLogger(__name__)

    try:
        # Connect to the localhosts database
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return None

        cursor = conn.cursor()

        # Query for the specific IP address - direct execution
        query = """
            SELECT ip_address, first_seen, original_flow,
                   mac_address, mac_vendor, dhcp_hostname, dns_hostname, os_fingerprint,
                   lease_hostname, lease_hwaddr, lease_clientid, acknowledged, local_description, icon,
                   tags, threat_score, alerts_enabled, management_link, last_seen, last_dhcp_discover, whitelisted,
                   total_packets_src, total_packets_dst, total_bytes_src, total_bytes_dst, ip6_address, alert_if_offline, domain_name, docker_host
            FROM localhosts
            WHERE ip_address = ? OR mac_address = ?
        """

        # Execute the query directly
        cursor.execute(query, (ip_address, ip_address))

        # Fetch the result
        row = cursor.fetchone()

        # Check if any row was returned
        if not row:
            log_info(logger, f"[INFO] No localhost found with IP address: {ip_address}")
            return None

        return row

    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while retrieving localhost with IP {ip_address}: {e}",
        )
        return None
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while retrieving localhost with IP {ip_address}: {e}",
        )
        return None
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def get_localhosts_all():
    """
    Retrieve all localhost records with complete details from the localhosts database.

    Returns:
        list: A list of dictionaries containing all columns for each localhost entry,
              or an empty list if an error occurs.
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db("localhosts")

    if not conn:
        log_error(logger, "[ERROR] Unable to connect to localhosts database")
        return []

    try:
        cursor = conn.cursor()
        query = """
            SELECT ip_address, first_seen, original_flow,
                   mac_address, mac_vendor, dhcp_hostname, dns_hostname, os_fingerprint,
                   lease_hostname, lease_hwaddr, lease_clientid, acknowledged, local_description, icon, tags, threat_score, alerts_enabled, management_link, last_seen, last_dhcp_discover, whitelisted,
                   total_packets_src, total_packets_dst, total_bytes_src, total_bytes_dst, ip6_address, alert_if_offline, domain_name, docker_host
            FROM localhosts
        """
        cursor.execute(query)
        rows = cursor.fetchall()

        # Get column names from cursor description
        columns = [column[0] for column in cursor.description]

        # Convert rows to list of dictionaries with column names as keys
        localhosts = []
        for row in rows:
            localhost_dict = dict(zip(columns, row))
            localhosts.append(localhost_dict)

        log_info(
            logger,
            f"[INFO] Retrieved {len(localhosts)} localhost records with full details",
        )
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Failed to retrieve localhost records: {e}")
        return []
    finally:
        disconnect_from_db(conn)

    add_connected_network_details(localhosts)
    return localhosts


def get_localhosts():
    """
    Retrieve all local hosts from the localhosts database.

    Returns:
        set: A set of IP addresses from the localhosts database, or an empty set if an error occurs.
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db("localhosts")

    if not conn:
        log_error(logger, "[ERROR] Unable to connect to localhosts database")
        return set()

    try:
        cursor = conn.cursor()
        query = "SELECT ip_address FROM localhosts"
        cursor.execute(query)
        rows = cursor.fetchall()
        # Convert results to a set of IP addresses
        localhosts = set(row[0] for row in rows)
        log_info(
            logger, f"[INFO] Retrieved {len(localhosts)} local hosts from the database"
        )
        return localhosts

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Failed to retrieve local hosts: {e}")
        return set()
    finally:
        disconnect_from_db(conn)


def update_localhosts(
    ip_address,
    mac_vendor=None,
    dhcp_hostname=None,
    dns_hostname=None,
    os_fingerprint=None,
    lease_hostname=None,
    lease_hwaddr=None,
    lease_clientid=None,
):
    """
    Update or insert a record in the localhosts database for a given IP address.

    Args:
        ip_address (str): The IP address to update or insert.
        first_seen (str): The first seen timestamp in ISO format (optional).
        original_flow (str): The original flow information as a JSON string (optional).
        mac_address (str): The MAC address associated with the IP address (optional).
        mac_vendor (str): The vendor of the MAC address (optional).
        dhcp_hostname (str): The hostname from DHCP (optional).
        dns_hostname (str): The hostname from DNS (optional).
        os_fingerprint (str): The operating system fingerprint (optional).

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db("localhosts")

    if not conn:
        log_error(logger, "[ERROR] Unable to connect to localhosts database")
        return False

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE localhosts
            SET
                mac_vendor = COALESCE(?, mac_vendor),
                dhcp_hostname = COALESCE(?, dhcp_hostname),
                dns_hostname = COALESCE(?, dns_hostname),
                os_fingerprint = COALESCE(?, os_fingerprint),
                lease_hwaddr = COALESCE(?, lease_hwaddr),
                lease_clientid = COALESCE(?, lease_clientid),
                lease_hostname = COALESCE(?, lease_hostname)
            WHERE ip_address = ? OR mac_address = ?
        """,
            (
                mac_vendor,
                dhcp_hostname,
                dns_hostname,
                os_fingerprint,
                lease_hwaddr,
                lease_clientid,
                lease_hostname,
                ip_address,
                ip_address,
            ),
        )
        log_info(logger, f"[INFO] Discovery updated record for IP: {ip_address}")

        conn.commit()
        return True
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Failed to update localhosts database: {e}")
        return False
    finally:
        disconnect_from_db(conn)


def insert_localhost_basic(ip_address, original_flow=None):
    """
    Insert a new basic localhost record into the database.

    Args:
        ip_address (str): The IP address of the localhost (required)
        original_flow (str/dict): The original flow information as a JSON string or dict (optional)

    Returns:
        bool: True if the insertion was successful, False otherwise
    """
    logger = logging.getLogger(__name__)

    try:
        # Connect to the localhosts database
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()

        # Convert dict to JSON string if necessary
        if original_flow and isinstance(original_flow, dict):
            original_flow = json.dumps(original_flow)

        # Insert the localhost record
        cursor.execute(
            "INSERT INTO localhosts (ip_address, first_seen, original_flow) VALUES (?, datetime('now', 'localtime'), ?)",
            (ip_address, original_flow),
        )

        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully inserted basic localhost record for IP: {ip_address}",
        )
        return True

    except sqlite3.IntegrityError:
        # Handle case where IP already exists
        # log_warn(logger, f"[WARN] Localhost with IP: {ip_address} already exists in database")
        return False
    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while inserting localhost {ip_address}: {e}",
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while inserting localhost {ip_address}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def classify_localhost(
    ip_address,
    description,
    icon,
    management_link,
    mac_address,
    *,
    docker_host=_UNSET,
    identifier=None,
):
    """
    Classify a localhost by setting its description, icon, acknowledged status, management link, and optionally mac_address.

    Args:
        ip_address (str): The IP address of the localhost to classify
        description (str): A descriptive label for the localhost
        icon (str): The icon identifier to use for this device
        management_link (str): Management link for the device
        mac_address (str, optional): The MAC address to update (if provided)
        docker_host: Server inventory IP, None to clear, or omitted to preserve.
        identifier: Original IP or MAC when changing the device's IP.

    Returns:
        bool: True if the classification was successful, False otherwise
    """
    logger = logging.getLogger(__name__)

    try:
        conn = connect_to_db("localhosts")
        if not conn:
            raise sqlite3.OperationalError("Unable to connect to localhosts database")

        cursor = conn.cursor()

        # Ensure MAC address is saved as uppercase
        mac_address_upper = mac_address.upper() if mac_address else None
        identifier = identifier or ip_address
        with conn:
            cursor.execute(
                """
                SELECT ip_address, icon, docker_host FROM localhosts
                WHERE ip_address = ? OR mac_address = ? OR mac_address = ?
                """,
                (identifier, identifier, mac_address_upper),
            )
            current = cursor.fetchone()
            if current is None:
                raise LookupError(f"No local host found with IP or MAC: {identifier}")
            old_ip, current_icon, current_docker_host = current
            icon = current_icon if icon is None else icon
            if icon == "DOCKER CONTAINER":
                icon = "DOCKER_CONTAINER"
            if docker_host is _UNSET:
                docker_host = (
                    current_docker_host if icon == "DOCKER_CONTAINER" else None
                )
            if docker_host is not None:
                if icon != "DOCKER_CONTAINER":
                    raise ValueError(
                        "docker_host is only allowed for DOCKER_CONTAINER devices"
                    )
                if not isinstance(docker_host, str) or not docker_host:
                    raise ValueError(
                        "docker_host must be a server inventory IP or null"
                    )
                if docker_host in (old_ip, ip_address):
                    raise ValueError("A Docker container cannot host itself")
                cursor.execute(
                    """
                    SELECT 1 FROM localhosts
                    WHERE ip_address = ? AND icon IN ('LINUX_SERVER', 'WINDOWS_SERVER')
                    """,
                    (docker_host,),
                )
                if cursor.fetchone() is None:
                    raise ValueError(
                        "docker_host must reference a local LINUX_SERVER or WINDOWS_SERVER"
                    )

            cursor.execute(
                """
                UPDATE localhosts
                SET local_description = ?, icon = ?, acknowledged = 1,
                    management_link = ?, mac_address = ?, ip_address = ?, docker_host = ?
                WHERE ip_address = ?
                """,
                (
                    description,
                    icon,
                    management_link,
                    mac_address_upper,
                    ip_address,
                    docker_host,
                    old_ip,
                ),
            )
            cursor.execute(
                "UPDATE localhosts SET docker_host = ? WHERE docker_host = ?",
                (
                    ip_address if icon in ("LINUX_SERVER", "WINDOWS_SERVER") else None,
                    old_ip,
                ),
            )

        log_info(
            logger,
            f"[INFO] Classifying localhost {ip_address} as '{description}' with icon '{icon}'"
            + (f" and MAC '{mac_address_upper}'" if mac_address_upper else ""),
        )
        return True

    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while classifying localhost {ip_address}: {e}",
        )
        raise
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def delete_localhost_database(ip_address):
    """
    Delete a localhost record from the database and remove all related alerts and flows.

    Args:
        ip_address (str): The IP address of the localhost to delete

    Returns:
        bool: True if the deletion was successful, False otherwise
    """
    logger = logging.getLogger(__name__)

    try:
        # Connect to the localhosts database
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()

        # Delete the localhost record
        cursor.execute(
            """
            UPDATE localhosts SET docker_host = NULL
            WHERE docker_host IN (
                SELECT ip_address FROM localhosts WHERE ip_address = ? OR mac_address = ?
            )
            """,
            (ip_address, ip_address),
        )
        cursor.execute(
            "DELETE FROM localhosts WHERE ip_address = ? or mac_address = ?",
            (ip_address, ip_address),
        )
        localhost_deleted = cursor.rowcount > 0
        if localhost_deleted:
            conn.commit()
            log_info(
                logger, f"[INFO] Successfully deleted localhost with IP: {ip_address}"
            )
        else:
            log_warn(
                logger, f"[WARN] No localhost found with IP {ip_address} to delete"
            )

        # Delete related alerts
        conn_alerts = connect_to_db("alerts")
        if conn_alerts:
            cursor_alerts = conn_alerts.cursor()
            cursor_alerts.execute(
                "DELETE FROM alerts WHERE ip_address = ?", (ip_address,)
            )
            conn_alerts.commit()
            log_info(logger, f"[INFO] Deleted alerts for IP: {ip_address}")
            disconnect_from_db(conn_alerts)

        # Delete related flows from allflows where src_ip or dst_ip matches
        conn_flows = connect_to_db("allflows")
        if conn_flows:
            cursor_flows = conn_flows.cursor()
            cursor_flows.execute(
                "DELETE FROM allflows WHERE src_ip = ? OR dst_ip = ?",
                (ip_address, ip_address),
            )
            conn_flows.commit()
            log_info(logger, f"[INFO] Deleted flows from allflows for IP: {ip_address}")
            disconnect_from_db(conn_flows)

        conn_flows = connect_to_db("dnsqueries")
        if conn_flows:
            cursor_flows = conn_flows.cursor()
            cursor_flows.execute(
                "DELETE FROM dnsqueries WHERE client_ip = ?", (ip_address,)
            )
            conn_flows.commit()
            log_info(
                logger,
                f"[INFO] Deleted dns queries from dnsqueries for IP: {ip_address}",
            )
            disconnect_from_db(conn_flows)

        return localhost_deleted

    except sqlite3.Error as e:
        log_error(
            logger, f"[ERROR] Database error while deleting localhost {ip_address}: {e}"
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while deleting localhost {ip_address}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_localhost_threat_score(identifier, threat_score):
    """
    Update the threat score for a localhost in the database by IP address or MAC address.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        # First check if the localhost exists
        cursor.execute(
            "SELECT 1 FROM localhosts WHERE ip_address = ? OR mac_address = ?",
            (identifier, identifier),
        )
        if not cursor.fetchone():
            log_warn(
                logger,
                f"[WARN] No localhost found with IP or MAC {identifier} to update threat score",
            )
            return False

        cursor.execute(
            """
            UPDATE localhosts
            SET threat_score = ?
            WHERE ip_address = ? OR mac_address = ?
        """,
            (threat_score, identifier, identifier),
        )

        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully updated threat score for {identifier} to {threat_score}",
        )
        return True

    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while updating threat score for {identifier}: {e}",
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while updating threat score for {identifier}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_localhost_whitelisted(identifier, whitelisted):
    """
    Update the whitelisted flag for a localhost in the database by IP address or MAC address.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        # First check if the localhost exists
        cursor.execute(
            "SELECT 1 FROM localhosts WHERE ip_address = ? OR mac_address = ?",
            (identifier, identifier),
        )
        if not cursor.fetchone():
            log_warn(
                logger,
                f"[WARN] No localhost found with IP or MAC {identifier} to update whitelisted flag",
            )
            return False

        whitelisted_int = 1 if whitelisted else 0

        cursor.execute(
            """
            UPDATE localhosts
            SET whitelisted = ?
            WHERE ip_address = ? OR mac_address = ?
            """,
            (whitelisted_int, identifier, identifier),
        )

        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully updated whitelisted for {identifier} to {whitelisted}",
        )
        return True

    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while updating whitelisted for {identifier}: {e}",
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while updating whitelisted for {identifier}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_localhost_alerts_enabled(identifier, alerts_enabled):
    """
    Update the alerts_enabled flag for a localhost in the database by IP address or MAC address.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        # First check if the localhost exists
        cursor.execute(
            "SELECT 1 FROM localhosts WHERE ip_address = ? OR mac_address = ?",
            (identifier, identifier),
        )
        if not cursor.fetchone():
            log_warn(
                logger,
                f"[WARN] No localhost found with IP or MAC {identifier} to update alerts_enabled flag",
            )
            return False

        alerts_enabled_int = 1 if alerts_enabled else 0

        cursor.execute(
            """
            UPDATE localhosts
            SET alerts_enabled = ?
            WHERE ip_address = ? OR mac_address = ?
        """,
            (alerts_enabled_int, identifier, identifier),
        )

        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully updated alerts_enabled for {identifier} to {alerts_enabled}",
        )
        return True

    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while updating alerts_enabled for {identifier}: {e}",
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while updating alerts_enabled for {identifier}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_localhost_alert_if_offline(identifier, alert_if_offline):
    """
    Update the alert_if_offline flag for a localhost in the database by IP address or MAC address.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM localhosts WHERE ip_address = ? OR mac_address = ?",
            (identifier, identifier),
        )
        if not cursor.fetchone():
            log_warn(
                logger,
                f"[WARN] No localhost found with IP or MAC {identifier} to update alert_if_offline flag",
            )
            return False

        alert_if_offline_int = 1 if alert_if_offline else 0

        cursor.execute(
            """
            UPDATE localhosts
            SET alert_if_offline = ?
            WHERE ip_address = ? OR mac_address = ?
        """,
            (alert_if_offline_int, identifier, identifier),
        )

        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully updated alert_if_offline for {identifier} to {alert_if_offline}",
        )
        return True

    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while updating alert_if_offline for {identifier}: {e}",
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while updating alert_if_offline for {identifier}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def delete_alerts_by_ip(ip_address):
    """
    Delete all alerts for the specified IP address from the alerts database.

    Args:
        ip_address (str): The IP address for which all alerts should be deleted

    Returns:
        tuple: (success, count) where:
               - success (bool): True if the operation was successful
               - count (int): Number of alerts deleted
    """
    logger = logging.getLogger(__name__)

    try:
        # Connect to the alerts database
        conn = connect_to_db("alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return False, 0

        cursor = conn.cursor()

        # First get the count for logging purposes
        cursor.execute(
            "SELECT COUNT(*) FROM alerts WHERE ip_address = ?", (ip_address,)
        )
        count = cursor.fetchone()[0]

        if count == 0:
            log_info(logger, f"[INFO] No alerts found for IP {ip_address} to delete")
            return True, 0

        # Delete all alerts for the specified IP address
        cursor.execute("DELETE FROM alerts WHERE ip_address = ?", (ip_address,))

        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully deleted {count} alerts for IP address: {ip_address}",
        )
        return True, count

    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while deleting alerts for IP {ip_address}: {e}",
        )
        return False, 0
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while deleting alerts for IP {ip_address}: {e}",
        )
        return False, 0
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def get_average_threat_score():
    """
    Calculate and return the average threat score from all localhosts as a whole integer, rounded up.

    Returns:
        int: The average threat score rounded up to the nearest integer, or None if there are no records or an error occurs.
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db("localhosts")
    if not conn:
        log_error(logger, "[ERROR] Unable to connect to localhosts database")
        return None

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT AVG(threat_score) FROM localhosts WHERE threat_score IS NOT NULL"
        )
        result = cursor.fetchone()
        avg_score = math.ceil(result[0]) if result and result[0] is not None else None
        log_info(
            logger,
            f"[INFO] Average threat score for all localhosts (rounded up): {avg_score}",
        )
        return avg_score
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Failed to calculate average threat score: {e}")
        return None
    finally:
        disconnect_from_db(conn)


def insert_localhost_basic_by_mac(mac_address):
    """
    Insert a new basic localhost record into the database using MAC address only,
    but only if it does not already exist.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        # Check if MAC already exists
        cursor.execute("SELECT 1 FROM localhosts WHERE mac_address = ?", (mac_address,))
        if cursor.fetchone():
            log_info(
                logger,
                f"[INFO] MAC address {mac_address} already exists in localhosts database. No insert performed.",
            )
            return False

        cursor.execute(
            "INSERT INTO localhosts (mac_address, first_seen) VALUES (?, datetime('now', 'localtime'))",
            (mac_address,),
        )
        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully inserted basic localhost record for MAC: {mac_address}",
        )
        return True

    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Database error while inserting localhost {mac_address}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def get_localhost(identifier):
    """
    Retrieve complete details for a specific localhost record by IP address or MAC address.
    Args:
        identifier (str): The IP address or MAC address of the localhost to retrieve.
    Returns:
        dict: A dictionary containing all columns for the specified localhost,
              or None if the localhost is not found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return None

        cursor = conn.cursor()
        query = """
            SELECT ip_address, first_seen, original_flow,
                   mac_address, mac_vendor, dhcp_hostname, dns_hostname, os_fingerprint,
                   lease_hostname, lease_hwaddr, lease_clientid, acknowledged, local_description, icon, tags, threat_score, alerts_enabled, management_link, ip6_address, alert_if_offline, docker_host
            FROM localhosts
            WHERE ip_address = ? OR mac_address = ?
        """
        cursor.execute(query, (identifier, identifier))
        row = cursor.fetchone()
        if not row:
            log_info(logger, f"[INFO] No localhost found with IP or MAC: {identifier}")
            return None

        columns = [column[0] for column in cursor.description]
        localhost = dict(zip(columns, row))
    except Exception as e:
        log_error(logger, f"[ERROR] Error retrieving localhost: {e}")
        return None
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)

    add_connected_network_details([localhost])
    return localhost


def delete_localhost(identifier):
    """
    Delete a localhost record from the database using IP address or MAC address.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE localhosts SET docker_host = NULL
            WHERE docker_host IN (
                SELECT ip_address FROM localhosts WHERE ip_address = ? OR mac_address = ?
            )
            """,
            (identifier, identifier),
        )
        cursor.execute(
            "DELETE FROM localhosts WHERE ip_address = ? OR mac_address = ?",
            (identifier, identifier),
        )
        localhost_deleted = cursor.rowcount > 0
        if localhost_deleted:
            conn.commit()
            log_info(
                logger,
                f"[INFO] Successfully deleted localhost with IP or MAC: {identifier}",
            )
        else:
            log_warn(
                logger,
                f"[WARN] No localhost found with IP or MAC: {identifier} to delete",
            )
        return localhost_deleted

    except sqlite3.Error as e:
        log_error(
            logger, f"[ERROR] Database error while deleting localhost {identifier}: {e}"
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while deleting localhost {identifier}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_localhost_last_dhcp_discover(mac_address):
    """
    Update the last_dhcp_discover timestamp for a localhost in the database by MAC address only.
    Sets last_dhcp_discover to the current local time.

    Args:
        mac_address (str): The MAC address of the localhost to update.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        mac_address_upper = mac_address.upper()
        cursor.execute(
            """
            UPDATE localhosts
            SET last_dhcp_discover = datetime('now', 'localtime')
            WHERE mac_address = ?
        """,
            (mac_address_upper,),
        )
        if cursor.rowcount > 0:
            conn.commit()
            log_info(
                logger,
                f"[INFO] Updated last_dhcp_discover for MAC: {mac_address_upper}",
            )
            return True
        else:
            log_warn(
                logger,
                f"[WARN] No localhost found with MAC: {mac_address_upper} to update last_dhcp_discover",
            )
            return False
    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while updating last_dhcp_discover for MAC {mac_address}: {e}",
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while updating last_dhcp_discover for MAC {mac_address}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_localhost_ip6_address(identifier, ip6_address):
    """
    Update the ip6_address for a localhost in the database by IP address or MAC address.

    Args:
        identifier (str): The IPv4 address or MAC address of the localhost to update.
        ip6_address (str): The IPv6 address to store, or None to clear it.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM localhosts WHERE ip_address = ? OR mac_address = ?",
            (identifier, identifier),
        )
        if not cursor.fetchone():
            log_warn(
                logger,
                f"[WARN] No localhost found with IP or MAC {identifier} to update ip6_address",
            )
            return False

        cursor.execute(
            """
            UPDATE localhosts
            SET ip6_address = ?
            WHERE ip_address = ? OR mac_address = ?
        """,
            (ip6_address, identifier, identifier),
        )
        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully updated ip6_address for {identifier} to {ip6_address}",
        )
        return True

    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while updating ip6_address for {identifier}: {e}",
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while updating ip6_address for {identifier}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_localhost_domain_name(identifier, domain_name):
    """
    Update the domain_name for a localhost in the database by IP address or MAC address.

    Args:
        identifier (str): The IPv4 address or MAC address of the localhost to update.
        domain_name (str): The domain name to store (e.g. "server.example.com"),
            or None to clear it.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM localhosts WHERE ip_address = ? OR mac_address = ?",
            (identifier, identifier),
        )
        if not cursor.fetchone():
            log_warn(
                logger,
                f"[WARN] No localhost found with IP or MAC {identifier} to update domain_name",
            )
            return False

        cursor.execute(
            """
            UPDATE localhosts
            SET domain_name = ?
            WHERE ip_address = ? OR mac_address = ?
        """,
            (domain_name, identifier, identifier),
        )
        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully updated domain_name for {identifier} to {domain_name}",
        )
        return True

    except sqlite3.Error as e:
        log_error(
            logger,
            f"[ERROR] Database error while updating domain_name for {identifier}: {e}",
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while updating domain_name for {identifier}: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_localhost_stats(ip_address, src_packets, dst_packets, src_bytes, dst_bytes):
    """
    Increment total_packets_src, total_packets_dst, total_bytes_src, total_bytes_dst for a localhost entry, and update last_seen timestamp.

    Args:
        ip_address (str): The IPv4 address of the localhost to update.
        src_packets (int): Number of source packets to add.
        dst_packets (int): Number of destination packets to add.
        src_bytes (int): Number of source bytes to add.
        dst_bytes (int): Number of destination bytes to add.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE localhosts
            SET total_packets_src = COALESCE(total_packets_src, 0) + ?,
                total_packets_dst = COALESCE(total_packets_dst, 0) + ?,
                total_bytes_src = COALESCE(total_bytes_src, 0) + ?,
                total_bytes_dst = COALESCE(total_bytes_dst, 0) + ?,
                last_seen = datetime('now', 'localtime')
            WHERE ip_address = ?
            """,
            (src_packets, dst_packets, src_bytes, dst_bytes, ip_address),
        )
        conn.commit()
        log_info(
            logger,
            f"[INFO] Updated localhost {ip_address}: +{src_packets} src_packets, +{dst_packets} dst_packets, +{src_bytes} src_bytes, +{dst_bytes} dst_bytes",
        )
        return True
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while updating localhost stats: {e}")
        return False
    except Exception as e:
        log_error(
            logger, f"[ERROR] Unexpected error while updating localhost stats: {e}"
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def get_localhost_as_dict(ip_address):
    """Return a single localhost record as a dict, or None if not found."""
    row = get_localhost_by_ip(ip_address)
    if not row:
        return None
    columns = [
        "ip_address",
        "first_seen",
        "original_flow",
        "mac_address",
        "mac_vendor",
        "dhcp_hostname",
        "dns_hostname",
        "os_fingerprint",
        "lease_hostname",
        "lease_hwaddr",
        "lease_clientid",
        "acknowledged",
        "local_description",
        "icon",
        "tags",
        "threat_score",
        "alerts_enabled",
        "management_link",
        "last_seen",
        "last_dhcp_discover",
        "whitelisted",
        "total_packets_src",
        "total_packets_dst",
        "total_bytes_src",
        "total_bytes_dst",
        "ip6_address",
        "alert_if_offline",
        "domain_name",
        "docker_host",
    ]
    localhost = dict(zip(columns, row))
    add_connected_network_details([localhost])
    return localhost


def get_whitelisted_localhosts():
    """Return all localhost records where whitelisted = 1 as a list of dicts."""
    return [h for h in get_localhosts_all() if h.get("whitelisted") == 1]
