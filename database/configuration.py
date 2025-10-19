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




def get_config_settings():
    """Read configuration settings from the configuration database into a dictionary."""
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(CONST_CONFIGURATION_DB, "configuration")
        if not conn:
            log_error(logger,"[ERROR] Unable to connect to configuration database")
            return None

        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM configuration")
        config_dict = dict(cursor.fetchall())
        log_info(logger, f"[INFO] Successfully loaded {len(config_dict)} configuration settings")
        return config_dict
    except sqlite3.Error as e:
        log_error(logger,f"[ERROR] Error reading configuration database: {e}")
        disconnect_from_db(conn)
        return None
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def update_config_setting(key, value, silent=False):
    """
    Insert or update a configuration setting in the database.
    
    Args:
        key (str): The configuration key
        value (str): The configuration value
        
    Returns:
        bool: True if the operation was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the configuration database
        conn = connect_to_db(CONST_CONFIGURATION_DB, "configuration")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to configuration database")
            return False
            
        cursor = conn.cursor()
        
        # Insert or replace the configuration setting
        cursor.execute("""
            INSERT OR REPLACE INTO configuration (key, value, last_changed) 
            VALUES (?, ?, datetime('now', 'localtime'))
        """, (key, value))
        
        # Commit the changes
        conn.commit()
        
        if not silent:
            log_info(logger, f"[INFO] Successfully updated configuration setting: {key}")
        return True
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while updating configuration setting: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while updating configuration setting: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def update_flow_metrics(last_packets, last_flows, last_bytes):
    """
    Update flow metrics in the configuration database.
    Stores/updates: Total Packets, Total Flows, Total Bytes, Last Packets, Last Flows, Last Bytes, Last Flow Seen.

    Args:
        last_packets (int): Number of packets in the last interval
        last_flows (int): Number of flows in the last interval
        last_bytes (int): Number of bytes in the last interval

    Returns:
        bool: True if all updates were successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    try:
        # Get current totals from config
        config = get_config_settings()
        total_packets = int(config.get("TotalPackets", 0))
        total_flows = int(config.get("TotalFlows", 0))
        total_bytes = int(config.get("TotalBytes", 0))

        # Update totals
        new_total_packets = total_packets + last_packets
        new_total_flows = total_flows + last_flows
        new_total_bytes = total_bytes + last_bytes

        # Update each value in the config database
        success = True
        success &= update_config_setting("TotalPackets", str(new_total_packets), silent=True)
        success &= update_config_setting("TotalFlows", str(new_total_flows), silent=True)
        success &= update_config_setting("TotalBytes", str(new_total_bytes), silent=True)
        success &= update_config_setting("LastPackets", str(last_packets), silent=True)
        success &= update_config_setting("LastFlows", str(last_flows), silent=True)
        success &= update_config_setting("LastBytes", str(last_bytes), silent=True)
        # Set Last Flow Seen to current timestamp
        from datetime import datetime
        last_flow_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if last_flows > 0 and last_packets > 0 and last_bytes > 0:
            success &= update_config_setting("LastFlowSeen", last_flow_seen, silent=True)

        if success:
            log_info(logger, f"[INFO] Successfully updated flow metrics in configuration database. Packets: {last_packets}, Flows: {last_flows}, Bytes: {last_bytes}")
        else:
            log_error(logger, "[ERROR] Failed to update one or more flow metrics in configuration database.")
        return success

    except Exception as e:
        log_error(logger, f"[ERROR] Exception in update_flow_metrics: {e}")
        return False
