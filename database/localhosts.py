import os
import sys
from database.core import connect_to_db, disconnect_from_db
from pathlib import Path
import math
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *

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
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return None

        cursor = conn.cursor()
        
        # Query for the specific IP address - direct execution
        query = """
            SELECT ip_address, first_seen, original_flow, 
                   mac_address, mac_vendor, dhcp_hostname, dns_hostname, os_fingerprint,
                   lease_hostname, lease_hwaddr, lease_clientid, acknowledged, local_description, icon, tags, threat_score, alerts_enabled, management_link
            FROM localhosts
            WHERE ip_address = ? OR mac_address = ?
        """
        
        # Execute the query directly
        cursor.execute(query, (ip_address,ip_address))
        
        # Fetch the result
        row = cursor.fetchone()
        
        # Check if any row was returned
        if not row:
            log_info(logger, f"[INFO] No localhost found with IP address: {ip_address}")
            return None
        
            
        return row
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving localhost with IP {ip_address}: {e}")
        return None
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving localhost with IP {ip_address}: {e}")
        return None
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_localhosts_all():
    """
    Retrieve all localhost records with complete details from the localhosts database.

    Returns:
        list: A list of dictionaries containing all columns for each localhost entry,
              or an empty list if an error occurs.
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")

    if not conn:
        log_error(logger, "[ERROR] Unable to connect to localhosts database")
        return []

    try:
        cursor = conn.cursor()
        query = """
            SELECT ip_address, first_seen, original_flow, 
                   mac_address, mac_vendor, dhcp_hostname, dns_hostname, os_fingerprint,
                   lease_hostname, lease_hwaddr, lease_clientid, acknowledged, local_description, icon, tags, threat_score, alerts_enabled, management_link
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

        log_info(logger, f"[INFO] Retrieved {len(localhosts)} localhost records with full details")
        return localhosts

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Failed to retrieve localhost records: {e}")
        return []
    finally:
        disconnect_from_db(conn)

def get_localhosts():
    """
    Retrieve all local hosts from the localhosts database.

    Returns:
        set: A set of IP addresses from the localhosts database, or an empty set if an error occurs.
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")

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
        log_info(logger, f"[INFO] Retrieved {len(localhosts)} local hosts from the database")
        return localhosts

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Failed to retrieve local hosts: {e}")
        return set()
    finally:
        disconnect_from_db(conn)

def update_localhosts(ip_address, mac_vendor=None, dhcp_hostname=None, dns_hostname=None, os_fingerprint=None, lease_hostname=None, lease_hwaddr=None, lease_clientid=None):
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
    conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")

    if not conn:
        log_error(logger, "[ERROR] Unable to connect to localhosts database")
        return False

    try:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE localhosts
            SET 
                mac_vendor = COALESCE(?, mac_vendor),
                dhcp_hostname = COALESCE(?, dhcp_hostname),
                dns_hostname = COALESCE(?, dns_hostname),
                os_fingerprint = COALESCE(?, os_fingerprint),
                lease_hwaddr = COALESCE(?, lease_hwaddr),
                lease_clientid = COALESCE(?, lease_clientid),
                lease_hostname = COALESCE(?, lease_hostname)
            WHERE ip_address = ? or mac_address = ?
        """, (mac_vendor, dhcp_hostname, dns_hostname, os_fingerprint, lease_hwaddr, lease_clientid, lease_hostname, ip_address, ip_address))
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
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
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
            (ip_address, original_flow)
        )
        
        conn.commit()
        log_info(logger, f"[INFO] Successfully inserted basic localhost record for IP: {ip_address}")
        return True
        
    except sqlite3.IntegrityError:
        # Handle case where IP already exists
        #log_warn(logger, f"[WARN] Localhost with IP: {ip_address} already exists in database")
        return False
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while inserting localhost {ip_address}: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while inserting localhost {ip_address}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def classify_localhost(ip_address, description, icon, management_link, mac_address):
    """
    Classify a localhost by setting its description, icon, acknowledged status, management link, and optionally mac_address.

    Args:
        ip_address (str): The IP address of the localhost to classify
        description (str): A descriptive label for the localhost
        icon (str): The icon identifier to use for this device
        management_link (str): Management link for the device
        mac_address (str, optional): The MAC address to update (if provided)

    Returns:
        bool: True if the classification was successful, False otherwise
    """
    logger = logging.getLogger(__name__)

    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()

        log_info(logger,f"[INFO] Classifying localhost {ip_address} as '{description}' with icon '{icon}'" +
                        (f" and MAC '{mac_address}'" if mac_address else ""))
        cursor.execute("""
            UPDATE localhosts
            SET local_description = ?, icon = ?, acknowledged = 1, management_link = ?, mac_address = ?, ip_address = ?
            WHERE ip_address = ? or mac_address = ?
        """, (description, icon, management_link, mac_address, ip_address, ip_address, mac_address))

        if cursor.rowcount > 0:
            conn.commit()
            log_info(logger, f"[INFO] Successfully classified localhost {ip_address} as '{description}' with icon '{icon}'" +
                              (f" and MAC '{mac_address}'" if mac_address else ""))
            return True
        else:
            log_warn(logger, f"[WARN] No localhost found with IP {ip_address} to classify")
            return False

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while classifying localhost {ip_address}: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while classifying localhost {ip_address}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
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
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        
        # Delete the localhost record
        cursor.execute("DELETE FROM localhosts WHERE ip_address = ? or mac_address = ?", (ip_address,ip_address))
        localhost_deleted = cursor.rowcount > 0
        if localhost_deleted:
            conn.commit()
            log_info(logger, f"[INFO] Successfully deleted localhost with IP: {ip_address}")
        else:
            log_warn(logger, f"[WARN] No localhost found with IP {ip_address} to delete")
        
        # Delete related alerts
        conn_alerts = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if conn_alerts:
            cursor_alerts = conn_alerts.cursor()
            cursor_alerts.execute("DELETE FROM alerts WHERE ip_address = ?", (ip_address,))
            conn_alerts.commit()
            log_info(logger, f"[INFO] Deleted alerts for IP: {ip_address}")
            disconnect_from_db(conn_alerts)
        
        # Delete related flows from allflows where src_ip or dst_ip matches
        conn_flows = connect_to_db(CONST_CONSOLIDATED_DB, "allflows")
        if conn_flows:
            cursor_flows = conn_flows.cursor()
            cursor_flows.execute("DELETE FROM allflows WHERE src_ip = ? OR dst_ip = ?", (ip_address, ip_address))
            conn_flows.commit()
            log_info(logger, f"[INFO] Deleted flows from allflows for IP: {ip_address}")
            disconnect_from_db(conn_flows)

        conn_flows = connect_to_db(CONST_CONSOLIDATED_DB, "dnsqueries")
        if conn_flows:
            cursor_flows = conn_flows.cursor()
            cursor_flows.execute("DELETE FROM dnsqueries WHERE client_ip = ?", (ip_address,))
            conn_flows.commit()
            log_info(logger, f"[INFO] Deleted dns queries from dnsqueries for IP: {ip_address}")
            disconnect_from_db(conn_flows)
        
        return localhost_deleted
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while deleting localhost {ip_address}: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while deleting localhost {ip_address}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def update_localhost_threat_score(identifier, threat_score):
    """
    Update the threat score for a localhost in the database by IP address or MAC address.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        # First check if the localhost exists
        cursor.execute("SELECT 1 FROM localhosts WHERE ip_address = ? OR mac_address = ?", (identifier, identifier))
        if not cursor.fetchone():
            log_warn(logger, f"[WARN] No localhost found with IP or MAC {identifier} to update threat score")
            return False

        cursor.execute("""
            UPDATE localhosts
            SET threat_score = ?
            WHERE ip_address = ? OR mac_address = ?
        """, (threat_score, identifier, identifier))

        conn.commit()
        log_info(logger, f"[INFO] Successfully updated threat score for {identifier} to {threat_score}")
        return True

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while updating threat score for {identifier}: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while updating threat score for {identifier}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def update_localhost_alerts_enabled(identifier, alerts_enabled):
    """
    Update the alerts_enabled flag for a localhost in the database by IP address or MAC address.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        # First check if the localhost exists
        cursor.execute("SELECT 1 FROM localhosts WHERE ip_address = ? OR mac_address = ?", (identifier, identifier))
        if not cursor.fetchone():
            log_warn(logger, f"[WARN] No localhost found with IP or MAC {identifier} to update alerts_enabled flag")
            return False

        alerts_enabled_int = 1 if alerts_enabled else 0

        cursor.execute("""
            UPDATE localhosts
            SET alerts_enabled = ?
            WHERE ip_address = ? OR mac_address = ?
        """, (alerts_enabled_int, identifier, identifier))

        conn.commit()
        log_info(logger, f"[INFO] Successfully updated alerts_enabled for {identifier} to {alerts_enabled}")
        return True

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while updating alerts_enabled for {identifier}: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while updating alerts_enabled for {identifier}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
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
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, f"[ERROR] Unable to connect to alerts database.")
            return False, 0

        cursor = conn.cursor()
        
        # First get the count for logging purposes
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE ip_address = ?", (ip_address,))
        count = cursor.fetchone()[0]
        
        if count == 0:
            log_info(logger, f"[INFO] No alerts found for IP {ip_address} to delete")
            return True, 0
        
        # Delete all alerts for the specified IP address
        cursor.execute("DELETE FROM alerts WHERE ip_address = ?", (ip_address,))
        
        conn.commit()
        log_info(logger, f"[INFO] Successfully deleted {count} alerts for IP address: {ip_address}")
        return True, count
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while deleting alerts for IP {ip_address}: {e}")
        return False, 0
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while deleting alerts for IP {ip_address}: {e}")
        return False, 0
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_average_threat_score():
    """
    Calculate and return the average threat score from all localhosts as a whole integer, rounded up.

    Returns:
        int: The average threat score rounded up to the nearest integer, or None if there are no records or an error occurs.
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
    if not conn:
        log_error(logger, "[ERROR] Unable to connect to localhosts database")
        return None

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT AVG(threat_score) FROM localhosts WHERE threat_score IS NOT NULL")
        result = cursor.fetchone()
        avg_score = math.ceil(result[0]) if result and result[0] is not None else None
        log_info(logger, f"[INFO] Average threat score for all localhosts (rounded up): {avg_score}")
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
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        # Check if MAC already exists
        cursor.execute("SELECT 1 FROM localhosts WHERE mac_address = ?", (mac_address,))
        if cursor.fetchone():
            log_info(logger, f"[INFO] MAC address {mac_address} already exists in localhosts database. No insert performed.")
            return False

        cursor.execute(
            "INSERT INTO localhosts (mac_address, first_seen) VALUES (?, datetime('now', 'localtime'))",
            (mac_address,)
        )
        conn.commit()
        log_info(logger, f"[INFO] Successfully inserted basic localhost record for MAC: {mac_address}")
        return True

    except Exception as e:
        log_error(logger, f"[ERROR] Database error while inserting localhost {mac_address}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
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
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return None

        cursor = conn.cursor()
        query = """
            SELECT ip_address, first_seen, original_flow, 
                   mac_address, mac_vendor, dhcp_hostname, dns_hostname, os_fingerprint,
                   lease_hostname, lease_hwaddr, lease_clientid, acknowledged, local_description, icon, tags, threat_score, alerts_enabled, management_link
            FROM localhosts
            WHERE ip_address = ? OR mac_address = ?
        """
        cursor.execute(query, (identifier, identifier))
        row = cursor.fetchone()
        if not row:
            log_info(logger, f"[INFO] No localhost found with IP or MAC: {identifier}")
            return None

        columns = [column[0] for column in cursor.description]
        return dict(zip(columns, row))
    except Exception as e:
        log_error(logger, f"[ERROR] Error retrieving localhost: {e}")
        return None
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def delete_localhost(identifier):
    """
    Delete a localhost record from the database using IP address or MAC address.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return False

        cursor = conn.cursor()
        cursor.execute("DELETE FROM localhosts WHERE ip_address = ? OR mac_address = ?", (identifier, identifier))
        localhost_deleted = cursor.rowcount > 0
        if localhost_deleted:
            conn.commit()
            log_info(logger, f"[INFO] Successfully deleted localhost with IP or MAC: {identifier}")
        else:
            log_warn(logger, f"[WARN] No localhost found with IP or MAC: {identifier} to delete")
        return localhost_deleted

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while deleting localhost {identifier}: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while deleting localhost {identifier}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def update_localhosts(identifier, mac_vendor=None, dhcp_hostname=None, dns_hostname=None, os_fingerprint=None, lease_hostname=None, lease_hwaddr=None, lease_clientid=None):
    """
    Update a record in the localhosts database for a given IP address or MAC address.

    Args:
        identifier (str): The IP address or MAC address to update.
        Other fields: Optional fields to update.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")

    if not conn:
        log_error(logger, "[ERROR] Unable to connect to localhosts database")
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("""
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
        """, (mac_vendor, dhcp_hostname, dns_hostname, os_fingerprint, lease_hwaddr, lease_clientid, lease_hostname, identifier, identifier))
        log_info(logger, f"[INFO] Discovery updated record for IP or MAC: {identifier}")

        conn.commit()
        return True
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Failed to update localhosts database: {e}")
        return False
    finally:
        disconnect_from_db(conn)