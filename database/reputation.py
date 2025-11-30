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
    conn = connect_to_db( table_name)
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO reputationlist (network, start_ip, end_ip, netmask)
            VALUES (?, ?, ?, ?)
        """, (
            network,
            start_ip,
            end_ip,
            netmask
        ))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"[ERROR] Error inserting into reputation database: {e}")
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
    conn = connect_to_db( table_name)
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT network, start_ip, end_ip, netmask FROM reputationlist")
        results = cursor.fetchall()
        return results
    except sqlite3.Error as e:
        logger.error(f"[ERROR] Error retrieving reputation records: {e}")
        return None
    finally:
        # Properly disconnect from the database
        disconnect_from_db(conn)