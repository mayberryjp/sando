import os
import sys
from database.core import connect_to_db, disconnect_from_db
from pathlib import Path
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *


def get_all_tor_nodes():
    """
    Retrieve all Tor node IP addresses from the database.
    
    Returns:
        list: A list of IP addresses of known Tor nodes.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    table_name = "tornodes"
    
    try:
        # Connect to database
        conn = connect_to_db( table_name)
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to tornodes database.")
            return []

        cursor = conn.cursor()
        
        # Retrieve all Tor node IP addresses
        cursor.execute("SELECT ip_address FROM tornodes")
        
        # Initialize empty array for tor nodes
        tor_nodes = []
        
        # Extract IP addresses one by one and add to array
        for row in cursor.fetchall():
            ip_address = row[0]  # Extract just the IP address
            tor_nodes.append(ip_address)  # Add it to the array
        
        log_info(logger, f"[INFO] Retrieved {len(tor_nodes)} Tor node IP addresses from database.")
        return tor_nodes
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving Tor nodes: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving Tor nodes: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def insert_tor_node(ip_address):
    """
    Insert a new Tor node record into the database.
    
    Args:
        ip_address: IP address of the Tor node
        
    Returns:
        True if insertion was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    table_name = "tornodes"
    
    # Connect to database
    conn = connect_to_db( table_name)
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tornodes (ip_address, import_date) 
            VALUES (?, datetime('now', 'localtime'))
        """, (ip_address,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"[ERROR] Error inserting Tor node into database: {e}")
        return False
    finally:
        # Properly disconnect from the database
        disconnect_from_db(conn)