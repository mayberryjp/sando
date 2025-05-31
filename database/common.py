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

def check_update_database_schema(config_dict):
    """
    Check if the database schema version matches the current version.
    If not, execute database schema updates and update the version.
    
    Args:
        config_dict (dict): Configuration dictionary containing settings
        
    Returns:
        bool: True if the operation was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    try:
        # Get the current schema version from constants
        from src.const import CONST_DATABASE_SCHEMA_VERSION
        
        # Schema file path
        schema_file_path = os.path.join(parent_dir, '/database', 'database.schema')
        
        # Read current schema version from file if it exists
        current_schema = '0'
        if os.path.exists(schema_file_path):
            try:
                with open(schema_file_path, 'r') as f:
                    current_schema = f.read().strip()
            except Exception as e:
                log_error(logger, f"[ERROR] Failed to read schema version file: {e}")
        
        # Check if the version matches the current version
        if current_schema != str(CONST_DATABASE_SCHEMA_VERSION):
            log_info(logger, f"[INFO] Database schema needs update: {current_schema} → {CONST_DATABASE_SCHEMA_VERSION}")
            
            # Execute schema update function
            if update_database_schema(current_schema, CONST_DATABASE_SCHEMA_VERSION):
                # Write the new schema version to file
                try:
                    os.makedirs(os.path.dirname(schema_file_path), exist_ok=True)
                    with open(schema_file_path, 'w') as f:
                        f.write(str(CONST_DATABASE_SCHEMA_VERSION))
                    
                    log_info(logger, f"[INFO] Database schema version updated to {CONST_DATABASE_SCHEMA_VERSION}")
                    return True
                except Exception as e:
                    log_error(logger, f"[ERROR] Failed to write schema version to file: {e}")
                    return False
            else:
                log_error(logger, "[ERROR] Failed to update database schema")
                return False
        else:
            log_info(logger, f"[INFO] Database schema is up to date (version {CONST_DATABASE_SCHEMA_VERSION})")
            return True
            
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while checking/updating schema version: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)


def update_database_schema(current_version, target_version):
    """
    Update the database schema from current_version to target_version
    by executing the necessary SQL commands.
    
    Args:
        current_version (str): The current schema version
        target_version (str): The target schema version to upgrade to
        
    Returns:
        bool: True if successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # This function will be implemented later with actual schema updates
        # For now, it's just a placeholder that returns success
        log_info(logger, f"[INFO] Executing schema update from version {current_version} to {target_version}")
        
        if target_version < 7:
            log_info(logger, "[INFO] Version is less than 7, deleting all flows")
            delete_all_records(CONST_CONSOLIDATED_DB, "allflows")
        

   # add additional schema updates here as needed
        if target_version < 8:
            pass
        
        return True
        
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to update database schema: {e}")
        return False


def store_site_name(site_name):
    """
    Store the site name in the configuration database with the key 'SiteName'.
    
    Args:
        site_name (str): The site name to store
        
    Returns:
        bool: True if the operation was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    try:
        # Validate input
        if not site_name or not isinstance(site_name, str):
            log_error(logger, "[ERROR] Invalid site name provided")
            return False
            
        # Connect to the configuration database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "configuration")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to configuration database")
            return False

        cursor = conn.cursor()

        # Insert or update the SiteName in the configuration table
        cursor.execute("""
            INSERT INTO configuration (key, value, last_changed)
            VALUES ('SiteName', ?, datetime('now', 'localtime'))
            ON CONFLICT(key)
            DO UPDATE SET value = excluded.value
        """, (site_name,))

        conn.commit()
        log_info(logger, f"[INFO] Site name stored successfully: {site_name}")
        return True

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while storing site name: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while storing site name: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def init_configurations_from_sitepy():
    """
    Inserts default configurations from file in /database into the CONST_CONSOLIDATED_DB database and returns a configuration dictionary.

    Returns:
        dict: A dictionary containing the configuration settings.
    """
    logger = logging.getLogger(__name__)
    config_dict = {}

    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "configuration")
        if not conn:
            log_error(logger,"[ERROR] Unable to connect to configuration database")
            return config_dict

        if IS_CONTAINER:
            SITE = os.getenv("SITE", CONST_SITE)

        # Dynamically import the site-specific configuration module
        config = importlib.import_module(f"{SITE}")
        log_info(logger, f"[INFO] Reading configuration from /database/{SITE}.py")

        cursor = conn.cursor()

        # Insert default configurations into the database
        for key, value in config.CONST_DEFAULT_CONFIGS:
            log_info(logger, f"[INFO] Inserting configuration: {key} = {value}")
            cursor.execute("""
                INSERT OR IGNORE INTO configuration (key, value, last_changed)
                VALUES (?, ?, datetime('now', 'localtime'))
            """, (key, value))
        conn.commit()

        # Fetch all configurations into a dictionary
        cursor.execute("SELECT key, value FROM configuration")
        config_dict = dict(cursor.fetchall())

        log_info(logger, f"[INFO] Default configurations initialized successfully.")
        disconnect_from_db(conn)
    except sqlite3.Error as e:
        log_error(logger,f"[ERROR] Error initializing default configurations: {e}")
    except Exception as e:
        log_error(logger,f"[ERROR] Unexpected error: {e}")
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)
    
    disconnect_from_db(conn)
    return config_dict

def init_configurations_from_variable():
    """
    Inserts default configurations into the CONST_CONSOLIDATED_DB database and returns a configuration dictionary.

    Returns:
        dict: A dictionary containing the configuration settings.
    """
    logger = logging.getLogger(__name__)
    config_dict = {}

    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "configuration")
        if not conn:
            log_error(logger,"[ERROR] Unable to connect to configuration database")
            return config_dict

        cursor = conn.cursor()

        # Insert default configurations into the database
        for key, value in CONST_INSTALL_CONFIGS:
            cursor.execute("""
                INSERT OR IGNORE INTO configuration (key, value, last_changed)
                VALUES (?, ?, datetime('now', 'localtime'))
            """, (key, value))
        conn.commit()

        # Fetch all configurations into a dictionary
        cursor.execute("SELECT key, value FROM configuration")
        config_dict = dict(cursor.fetchall())

        log_info(logger, f"[INFO] Default configurations initialized successfully.")
        disconnect_from_db(conn)
    except sqlite3.Error as e:
        log_error(logger,f"[ERROR] Error initializing default configurations: {e}")
    except Exception as e:
        log_error(logger,f"[ERROR] Unexpected error: {e}")
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)
    disconnect_from_db(conn)
    return config_dict

def collect_database_counts():
    """
    Collects counts from the alerts, localhosts, and ignorelist tables.

    Returns:
        dict: A dictionary containing the counts for acknowledged alerts, unacknowledged alerts,
              total alerts, localhosts entries, and ignorelist entries.
    """
    logger = logging.getLogger(__name__)
    counts = {
        "acknowledged_alerts": 0,
        "unacknowledged_alerts": 0,
        "total_alerts": 0,
        "unacknowledged_localhosts_count": 0,
        "acknowledged_localhosts_count": 0,
        "total_localhosts_count": 0,
        "ignorelist_count": 0,

    }

    try:
        # Connect to the alerts database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if conn:
            cursor = conn.cursor()
            # Count acknowledged alerts
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 1")
            counts["acknowledged_alerts"] = cursor.fetchone()[0]

            # Count unacknowledged alerts
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0")
            counts["unacknowledged_alerts"] = cursor.fetchone()[0]

            # Count total alerts
            cursor.execute("SELECT COUNT(*) FROM alerts")
            counts["total_alerts"] = cursor.fetchone()[0]

            conn.close()
        else:
            log_error(logger, "[ERROR] Unable to connect to alerts database")

        # Connect to the localhosts database
        conn_localhosts = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if conn_localhosts:
            cursor = conn_localhosts.cursor()
            # Count entries in localhosts
            cursor.execute("SELECT COUNT(*) FROM localhosts")
            counts["total_localhosts_count"] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM localhosts where acknowledged = 1")
            counts["acknowledged_localhosts_count"] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM localhosts WHERE acknowledged = 0")
            counts["unacknowledged_localhosts_count"] = cursor.fetchone()[0]

            conn_localhosts.close()
        else:
            log_error(logger, "[ERROR] Unable to connect to localhosts database")

        # Connect to the ignorelist database
        conn_ignorelist = connect_to_db(CONST_CONSOLIDATED_DB, "ignorelist")
        if conn_ignorelist:
            cursor = conn_ignorelist.cursor()
            # Count entries in ignorelist
            cursor.execute("SELECT COUNT(*) FROM ignorelist")
            counts["ignorelist_count"] = cursor.fetchone()[0]

            conn_ignorelist.close()
        else:
            log_error(logger, "[ERROR] Unable to connect to ignorelist database")

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error: {e}")
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error: {e}")

    return counts

def store_version():
    """
    Store the current version from CONST.py in the configuration database
    with the key 'Version'.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        # Import the version from CONST.py
        from src.const import VERSION
        
        # Connect to the configuration database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "configuration")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to configuration database.")
            return False

        cursor = conn.cursor()

        # Insert or update the Version in the configuration table
        cursor.execute("""
            INSERT INTO configuration (key, value, last_changed)
            VALUES ('Version', ?, datetime('now', 'localtime'))
            ON CONFLICT(key)
            DO UPDATE SET value = excluded.value
        """, (VERSION,))

        conn.commit()
        disconnect_from_db(conn)

        log_info(logger, f"[INFO] Version stored successfully: {VERSION}")
        return True

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while storing version: {e}")
        return False
    except ImportError as e:
        log_error(logger, f"[ERROR] Failed to import CONST_VERSION: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while storing version: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def store_machine_unique_identifier():
    """
    Generate a unique identifier for the machine and store it in the configuration database
    with the key 'MachineUniqueIdentifier'.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        # Generate the unique identifier
        unique_id = get_machine_unique_identifier()
        if not unique_id:
            log_error(logger, "[ERROR] Failed to generate machine unique identifier.")
            return False

        # Connect to the configuration database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "configuration")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to configuration database.")
            return False

        cursor = conn.cursor()

        # Insert or update the MachineUniqueIdentifier in the configuration table
        cursor.execute("""
            INSERT INTO configuration (key, value, last_changed)
            VALUES ('MachineUniqueIdentifier', ?, datetime('now', 'localtime'))
            ON CONFLICT(key)
            DO UPDATE SET value = excluded.value
        """, (unique_id,))

        conn.commit()
        disconnect_from_db(conn)

        log_info(logger, f"[INFO] Machine unique identifier stored successfully: {unique_id}")
        return True

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while storing machine unique identifier: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while storing machine unique identifier: {e}")
        return False

def get_machine_unique_identifier_from_db():
    """
    Retrieve the machine unique identifier from the configuration database.

    Returns:
        str: The machine unique identifier if found, None otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        # Connect to the configuration database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "configuration")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to configuration database.")
            return None

        cursor = conn.cursor()

        # Query the MachineUniqueIdentifier from the configuration table
        cursor.execute("""
            SELECT value FROM configuration WHERE key = 'MachineUniqueIdentifier'
        """)
        result = cursor.fetchone()

        disconnect_from_db(conn)

        if result:
            #log_info(logger, f"[INFO] Retrieved MachineUniqueIdentifier: {result[0]}")
            return result[0]
        else:
            log_error(logger, "[ERROR] MachineUniqueIdentifier not found in the configuration database.")
            return None

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving machine unique identifier: {e}")
        return None
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving machine unique identifier: {e}")
        return None
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)