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

def get_ignorelist():
    """
    Retrieve active entries from the ignorelist database.
    
    Returns:
        list: List of tuples containing (alert_id, category, insert_date)
              Returns None if there's an error
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "ignorelist")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to ignorelist database")
            return None

        cursor = conn.cursor()
        cursor.execute("""
            SELECT ignorelist_id, ignorelist_src_ip, ignorelist_dst_ip, ignorelist_dst_port, ignorelist_protocol
            FROM ignorelist 
            WHERE ignorelist_enabled = 1
        """)
        ignorelist = cursor.fetchall()

        log_info(logger, f"[INFO] Retrieved {len(ignorelist)} active ignorelist entries")
        
        return ignorelist

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error retrieving ignorelist entries: {e}")
        return None
    finally:
        if conn:
            disconnect_from_db(conn)

def import_ignorelists(config_dict):
    """
    Import ignorelist entries into the ignorelist database from a config_dict entry.

    Args:
        config_dict (dict): Configuration dictionary containing ignorelist entries.
                            Expected format: "IgnoreListEntries" -> JSON string of list of tuples
                            Each tuple: (src_ip, dst_ip, dst_port, protocol)
    """
    logger = logging.getLogger(__name__)
    ignorelist_entries_json = config_dict.get("IgnoreListEntries", "[]")
    if not ignorelist_entries_json:
        log_info(logger, "[INFO] No ignorelist entries found in config_dict.")
        return
    #print(f"[INFO] ignorelist_entries_json: {ignorelist_entries_json}")
    ignorelist_entries = json.loads(ignorelist_entries_json)

    if not ignorelist_entries:
        log_info(logger, "[INFO] No ignorelist entries found in config_dict.")
        return

    conn = connect_to_db(CONST_CONSOLIDATED_DB, "ignorelist")
    if not conn:
        log_error(logger, "[ERROR] Unable to connect to ignorelist database.")
        return

    try:
        cursor = conn.cursor()

        # Insert ignorelist entries into the database if they don't already exist
        for entry in ignorelist_entries:
            ignorelist_id, src_ip, dst_ip, dst_port, protocol = entry

            # Check if the ignorelist entry already exists
            cursor.execute("""
                SELECT COUNT(*) FROM ignorelist
                WHERE ignorelist_id = ? AND ignorelist_src_ip = ? AND ignorelist_dst_ip = ? AND ignorelist_dst_port = ? AND ignorelist_protocol = ?
            """, (ignorelist_id, src_ip, dst_ip, dst_port, protocol))
            exists = cursor.fetchone()[0]

            if exists:
                log_info(logger, f"[INFO] IgnoreList entry already exists: {entry}")
                continue
           
            # Insert the new ignorelist entry
            cursor.execute("""
                INSERT INTO ignorelist (
                    ignorelist_id, ignorelist_src_ip, ignorelist_dst_ip, ignorelist_dst_port, ignorelist_protocol, ignorelist_enabled, ignorelist_added, ignorelist_insert_date
                ) VALUES (?, ?, ?, ?, ?, 1, datetime('now', 'localtime'), datetime('now', 'localtime'))
            """, (ignorelist_id, src_ip, dst_ip, dst_port, protocol))

        conn.commit()
        log_info(logger, f"[INFO] Imported {len(ignorelist_entries)} ignorelist entries into the database.")

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error importing ignorelist entries: {e}")
    finally:
        disconnect_from_db(conn)

def delete_ignorelist_entry(ignorelist_id):
    """
    Delete an entry from the ignorelist database.
    
    Args:
        ignorelist_id (str): The ID of the ignorelist entry to delete
        
    Returns:
        bool: True if the deletion was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the ignorelist database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "ignorelist")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to ignorelist database.")
            return False

        cursor = conn.cursor()
        
        # Delete the ignorelist entry
        cursor.execute("DELETE FROM ignorelist WHERE ignorelist_id = ?", (ignorelist_id,))
        
        # Check if a row was affected
        if cursor.rowcount > 0:
            conn.commit()
            log_info(logger, f"[INFO] Successfully deleted ignorelist entry with ID: {ignorelist_id}")
            return True
        else:
            log_warn(logger, f"[WARN] No ignorelist entry found with ID {ignorelist_id} to delete")
            return False
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while deleting ignorelist entry {ignorelist_id}: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while deleting ignorelist entry {ignorelist_id}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def insert_ignorelist_entry(ignorelist_id, src_ip, dst_ip, dst_port, protocol):
    """
    Insert a new entry into the ignorelist database.
    
    Args:
        ignorelist_id (str): A unique identifier for the ignorelist entry
        src_ip (str): Source IP address to ignore
        dst_ip (str): Destination IP address to ignore
        dst_port (str): Destination port to ignore
        protocol (str): Protocol to ignore (e.g., 'tcp', 'udp')
        
    Returns:
        bool: True if the insertion was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the ignorelist database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "ignorelist")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to ignorelist database.")
            return False

        cursor = conn.cursor()
        
        # Check if the entry already exists
        cursor.execute("""
            SELECT COUNT(*) FROM ignorelist
            WHERE ignorelist_id = ? AND ignorelist_src_ip = ? AND ignorelist_dst_ip = ? 
            AND ignorelist_dst_port = ? AND ignorelist_protocol = ?
        """, (ignorelist_id, src_ip, dst_ip, dst_port, protocol))
        
        exists = cursor.fetchone()[0]
        if exists:
            log_info(logger, f"[INFO] Ignorelist entry already exists with ID: {ignorelist_id}")
            return True
        
        # Insert the new ignorelist entry
        cursor.execute("""
            INSERT INTO ignorelist (
                ignorelist_id, ignorelist_src_ip, ignorelist_dst_ip, ignorelist_dst_port, 
                ignorelist_protocol, ignorelist_enabled, ignorelist_added, ignorelist_insert_date
            ) VALUES (?, ?, ?, ?, ?, 1, datetime('now', 'localtime'), datetime('now', 'localtime'))
        """, (ignorelist_id, src_ip, dst_ip, dst_port, protocol))
        
        conn.commit()
        log_info(logger, f"[INFO] Successfully inserted new ignorelist entry with ID: {ignorelist_id}")
        return True
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while inserting ignorelist entry: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while inserting ignorelist entry: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_ignorelist_for_ip(local_ip):
    """
    Retrieve active ignorelist entries for a specific local IP address,
    including statistics from the tag statistics.
    
    Args:
        local_ip (str): The local IP address to filter by.
        
    Returns:
        list: List of dictionaries containing ignorelist entries with flow statistics
              for the specified local IP address.
              Returns an empty list if no entries are found or if there's an error.
    """
    logger = logging.getLogger(__name__)
    result = []
    
    try:
        # Connect to the ignorelist database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "ignorelist")
        if not conn:
            log_error(logger, f"[ERROR] Unable to connect to ignorelist database for IP {local_ip}")
            return result

        cursor = conn.cursor()
        cursor.execute("""
            SELECT ignorelist_id, ignorelist_src_ip, ignorelist_dst_ip, ignorelist_dst_port, ignorelist_protocol
            FROM ignorelist 
            WHERE ignorelist_enabled = 1 AND (ignorelist_src_ip = ? OR ignorelist_dst_ip = ?)
        """, (local_ip, local_ip))
        
        ignorelist_entries = cursor.fetchall()
        
        if not ignorelist_entries:
            log_info(logger, f"[INFO] No ignorelist entries found for IP {local_ip}")
            return result
        
        # Get all tag statistics once, instead of querying for each entry
        tag_stats_all = get_tag_statistics()

        # Create enhanced entries with statistics
        for entry in ignorelist_entries:
            ignorelist_id, src_ip, dst_ip, dst_port, protocol = entry
        
            tag_stats = tag_stats_all[f"IgnoreList_{ignorelist_id}"] if f"IgnoreList_{ignorelist_id}" in tag_stats_all else {}
            
            # Create enhanced entry
            enhanced_entry = {
                'id': ignorelist_id,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': protocol,
                'times_seen': tag_stats['count'] if tag_stats else 0,
                'first_seen': tag_stats['first_seen'] if tag_stats else None,
                'last_seen': tag_stats['last_seen'] if tag_stats else None
            }
            
            result.append(enhanced_entry)
        
        log_info(logger, f"[INFO] Retrieved {len(result)} enhanced ignorelist entries for IP {local_ip}")
        return result

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error retrieving ignorelist for IP {local_ip}: {e}")
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error retrieving ignorelist for IP {local_ip}: {e}")
        return result
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)