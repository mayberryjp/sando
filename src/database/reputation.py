import logging
import sqlite3

from src.database.core import connect_to_db, disconnect_from_db
from src.utils.locallogging import log_error
from src.utils.network import decode_ip_number, encode_network_range


def insert_reputation(network, start_ip, end_ip, netmask):
    """
    Insert a new reputation record into the database.

    Args:
        network: Network identifier (e.g., '192.168.1.0/24')
        start_ip: Starting IP address of range (as integer)
        end_ip: Ending IP address of range (as integer)
        netmask: Network mask

    Returns:
        True if insertion was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    table_name = "reputationlist"

    # Connect to database
    conn = connect_to_db(table_name)
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR IGNORE INTO reputationlist (network, start_ip, end_ip, netmask)
            VALUES (?, ?, ?, ?)
        """,
            encode_network_range(network, start_ip, end_ip, netmask),
        )
        conn.commit()
        return True
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error inserting into reputation database: {e}")
        return False
    finally:
        # Properly disconnect from the database
        disconnect_from_db(conn)


def get_all_reputation_records():
    """
    Retrieve all reputation records from the database.

    Returns:
        List of tuples containing reputation records or None if there's an error
    """
    logger = logging.getLogger(__name__)
    table_name = "reputationlist"

    # Connect to database
    conn = connect_to_db(table_name)
    if not conn:
        return None

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT network, start_ip, end_ip, netmask FROM reputationlist")
        results = cursor.fetchall()
        return [
            (network, decode_ip_number(start), decode_ip_number(end), decode_ip_number(mask))
            for network, start, end, mask in results
        ]
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error retrieving reputation records: {e}")
        return None
    finally:
        # Properly disconnect from the database
        disconnect_from_db(conn)
