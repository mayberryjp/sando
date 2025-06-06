import os
import sys
from database.core import connect_to_db, disconnect_from_db, run_timed_query
from pathlib import Path
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *

def insert_geolocation(rows):
    """
    Insert multiple geolocation records into the database.
    
    Args:
        rows: List of tuples, where each tuple contains:
              (network, start_ip, end_ip, netmask, country_name)
        
    Returns:
        tuple: (success_count, total_count) - number of successful insertions and total rows
    """
    logger = logging.getLogger(__name__)
    table_name = "geolocation"
    
    # Connect to database
    conn = connect_to_db(CONST_CONSOLIDATED_DB, table_name)
    if not conn:
        return (0, len(rows))
    
    try:
        cursor = conn.cursor()
        success_count = 0
        
        for row in rows:
            network, start_ip, end_ip, netmask, country_name = row
            
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO geolocation (
                        network, start_ip, end_ip, netmask, country_name
                    ) VALUES (?, ?, ?, ?, ?)
                """, (network, start_ip, end_ip, netmask, country_name))
                success_count += 1
            except sqlite3.Error as e:
                logger.error(f"[ERROR] Error inserting geolocation record {network}: {e}")
        
        conn.commit()
        logger.info(f"[INFO] Successfully inserted {success_count} of {len(rows)} geolocation records")
        return (success_count, len(rows))
    except sqlite3.Error as e:
        logger.error(f"[ERROR] Database error during bulk geolocation insert: {e}")
        return (0, len(rows))
    finally:
        # Properly disconnect from the database
        disconnect_from_db(conn)

def get_all_geolocations():
    """
    Retrieve all geolocation records from the database.
    
    Args:
        db_path: Path to the SQLite database file
        
    Returns:
        List of tuples containing geolocation records or None if there's an error
    """
    logger = logging.getLogger(__name__)
    table_name = "geolocation"
    
    # Connect to database
    conn = connect_to_db(CONST_CONSOLIDATED_DB, table_name)
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT network, start_ip, end_ip, netmask, country_name FROM geolocation")
        results = cursor.fetchall()
        return results
    except sqlite3.Error as e:
        logger.error(f"[ERROR] Error retrieving geolocation records: {e}")
        return None
    finally:
        # Properly disconnect from the database
        disconnect_from_db(conn)

def get_country_by_ip_int(ip_int):
    """
    Look up the country for an IP address represented as an integer.

    Args:
        ip_int (int): The IP address converted to an integer

    Returns:
        str: Country name if found, None otherwise
    """
    logger = logging.getLogger(__name__)
    table_name = "geolocation"

    # Connect to database
    conn = connect_to_db(CONST_CONSOLIDATED_DB, table_name)
    if not conn:
        logger.error(f"[ERROR] Failed to connect to the geolocation database")
        return None

    try:
        cursor = conn.cursor()
        # Find the range that contains this IP using run_timed_query
        query = """
            SELECT country_name 
            FROM geolocation 
            WHERE ? BETWEEN start_ip AND end_ip 
            LIMIT 1
        """
        rows, _ = run_timed_query(
            cursor,
            query,
            params=(ip_int,),
            description=f"get_country_by_ip_int",
            fetch_all=True
        )
        if rows:
            return rows[0][0]
        return None
    except sqlite3.Error as e:
        logger.error(f"[ERROR] Error looking up country for IP integer {ip_int}: {e}")
        return None
    finally:
        disconnect_from_db(conn)