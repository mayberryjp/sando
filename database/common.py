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
from database.core import delete_table, create_table
from database.configuration import update_config_setting
from database.localhosts import get_average_threat_score

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
                    
                    update_config_setting("DatabaseSchemaVersion", str(CONST_DATABASE_SCHEMA_VERSION))
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
        # Convert versions to integers for proper numerical comparison
        current_version_int = int(current_version)
        target_version_int = int(target_version)
        
        log_info(logger, f"[INFO] Executing schema update from version {current_version} to {target_version}")
        
        if current_version_int < 7:
            log_info(logger, "[INFO] Version is less than 7, deleting all flows")
            delete_all_records(CONST_CONSOLIDATED_DB, "allflows")

        if current_version_int < 8:
            log_info(logger, "[INFO] Version is less than 8, deleting all flows")
            delete_all_records(CONST_CONSOLIDATED_DB, "allflows")
        
        if current_version_int < 9:
            log_info(logger, "[INFO] Version is less than 9, deleting all actions")
            delete_all_records(CONST_CONSOLIDATED_DB, "actions")

        if current_version_int < 10:
            log_info(logger, "[INFO] Version is less than 10, alerting actions table")
            delete_table(CONST_CONSOLIDATED_DB, "actions")
            create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_ACTIONS_SQL, "actions")

        if current_version_int < 11:
            log_info(logger, "[INFO] Version is less than 11, alerting actions table")
            delete_table(CONST_CONSOLIDATED_DB, "actions")
            create_table(CONST_CONSOLIDATED_DB, CONST_CREATE_ACTIONS_SQL, "actions")

        if current_version_int < 12:
            log_info(logger, "[INFO] Version is less than 12, recreating explore view table")
            delete_table(CONST_EXPLORE_DB, "explore")
            create_table(CONST_EXPLORE_DB, CONST_CREATE_EXPLORE_SQL, "explore")
            
        if current_version_int < 13:
            log_info(logger, "[INFO] Version is less than 13, recreating explore view table")
            delete_all_records(CONST_PERFORMANCE_DB, "dbperformance")

        if current_version_int < 14:  #RESUME HERE #TODO: Implement migration logic
            log_info(logger, "[INFO] Version is less than 14, migrating configuration to dedicated configuration database")
            migrate_configurations_schema13_to_schema14()
           # delete_all_records(CONST_PERFORMANCE_DB, "dbperformance")

        if current_version_int < 15:  #RESUME HERE #TODO: Implement migration logic
            log_info(logger, "[INFO] Version is less than 15, migrating localhosts to dedicated configuration database")
            migrate_configurations_schema14_to_schema15()
           # delete_all_records(CONST_PERFORMANCE_DB, "dbperformance")

        return True
        
    except ValueError as e:
        log_error(logger, f"[ERROR] Invalid version format, could not convert to integer: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to update database schema: {e}")
        return False



def migrate_configurations_schema13_to_schema14():
    """
    Migrates configurations from CONSOLIDATED_DB to CONFIGURATION_DB.
    1. Gets all configurations from CONSOLIDATED_DB
    2. Deletes the configurations table in CONSOLIDATED_DB
    3. Creates a new configurations table in CONFIGURATION_DB
    4. Inserts all configurations into the new table
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting configuration migration from CONSOLIDATED_DB to CONFIGURATION_DB")

    
    try:
        # Step 1: Get all configurations from CONSOLIDATED_DB
        conn_consolidated = connect_to_db(CONST_CONSOLIDATED_DB, "configuration")
        if not conn_consolidated:
            log_error(logger, "[ERROR] Failed to connect to CONSOLIDATED_DB")
            return False
            
        cursor = conn_consolidated.cursor()
        cursor.execute("SELECT key, value, last_changed FROM configuration")
        rows = cursor.fetchall()

        
        delete_table(CONST_CONSOLIDATED_DB, "configuration")
        
        # Step 3: Create new configurations table in CONFIGURATION_DB
        conn_config = connect_to_db(CONST_CONFIGURATION_DB, "configuration")
        if not conn_config:
            log_error(logger, "[ERROR] Failed to connect to CONFIGURATION_DB")
            return False
            
        for row in rows:
            key, value, last_updated = row
            update_config_setting(key,value)

        log_info(logger, f"[INFO] Inserted {len(rows)} configuration entries into CONFIGURATION_DB")
        disconnect_from_db(conn_config)
        
        return True
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error during configuration migration: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error during configuration migration: {e}")
        return False
    finally:
        # Ensure all connections are closed
        if 'conn_consolidated' in locals() and conn_consolidated:
            disconnect_from_db(conn_consolidated)
        if 'conn_config' in locals() and conn_config:
            disconnect_from_db(conn_config)




def migrate_configurations_schema14_to_schema15():
    """
    Migrates all rows from the localhosts table in CONSOLIDATED_DB to LOCALHOSTS_DB.
    1. Gets all rows from localhosts in CONSOLIDATED_DB
    2. Deletes the localhosts table in CONSOLIDATED_DB
    3. Creates a new localhosts table in LOCALHOSTS_DB
    4. Inserts all rows into the new table in LOCALHOSTS_DB
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting localhost migration from CONSOLIDATED_DB to LOCALHOSTS_DB" )

    try:
        # Step 1: Get all rows from localhosts in CONSOLIDATED_DB
        conn_consolidated = connect_to_db(CONST_CONSOLIDATED_DB, "localhosts")
        if not conn_consolidated:
            log_error(logger, "[ERROR] Failed to connect to CONSOLIDATED_DB")
            return False

        cursor = conn_consolidated.cursor()
        cursor.execute("SELECT * FROM localhosts")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        # Step 2: Delete the localhosts table in CONSOLIDATED_DB
        delete_table(CONST_CONSOLIDATED_DB, "localhosts")
        delete_all_records(CONST_LOCALHOSTS_DB, "localhosts")

        # Step 3: Create new localhosts table in LOCALHOSTS_DB
        conn_localhosts = connect_to_db(CONST_LOCALHOSTS_DB, "localhosts")
        if not conn_localhosts:
            log_error(logger, "[ERROR] Failed to connect to LOCALHOSTS_DB")
            return False

        # Step 4: Insert all rows into the new table in LOCALHOSTS_DB
        cursor_localhosts = conn_localhosts.cursor()
        placeholders = ", ".join(["?"] * len(columns))
        insert_sql = f"INSERT INTO localhosts ({', '.join(columns)}) VALUES ({placeholders})"
        cursor_localhosts.executemany(insert_sql, rows)
        conn_localhosts.commit()

        log_info(logger, f"[INFO] Migrated {len(rows)} localhost entries into LOCALHOSTS_DB")
        disconnect_from_db(conn_localhosts)
        return True

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error during localhost migration: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error during localhost migration: {e}")
        return False
    finally:
        if 'conn_consolidated' in locals() and conn_consolidated:
            disconnect_from_db(conn_consolidated)
        if 'conn_localhosts' in locals() and conn_localhosts:
            disconnect_from_db(conn_localhosts)


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
        conn = connect_to_db(CONST_CONFIGURATION_DB, "configuration")
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
        conn = connect_to_db(CONST_CONFIGURATION_DB, "configuration")
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
        conn = connect_to_db(CONST_CONFIGURATION_DB, "configuration")
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
    Also retrieves flow statistics from configuration.

    Returns:
        dict: A dictionary containing database counts and flow statistics
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
        "average_threat_score": 0,
        "total_packets": 0,
        "total_flows": 0,
        "total_bytes": 0,
        "last_packets": 0,
        "last_flows": 0,
        "last_bytes": 0,
        "last_flow_seen": None,
        "is_healthy": "Down",
        "unacknowledged_actions": 0,
        "acknowledged_actions": 0,
        "total_actions": 0,
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

        conn = connect_to_db(CONST_CONSOLIDATED_DB, "actions")
        if conn:
            cursor = conn.cursor()
            # Count acknowledged alerts
            cursor.execute("SELECT COUNT(*) FROM actions WHERE acknowledged = 1")
            counts["acknowledged_actions"] = cursor.fetchone()[0]

            # Count unacknowledged alerts
            cursor.execute("SELECT COUNT(*) FROM actions WHERE acknowledged = 0")
            counts["unacknowledged_actions"] = cursor.fetchone()[0]

            # Count total alerts
            cursor.execute("SELECT COUNT(*) FROM actions")
            counts["total_actions"] = cursor.fetchone()[0]

            conn.close()
        else:
            log_error(logger, "[ERROR] Unable to connect to alerts database")

        # Connect to the localhosts database
        conn_localhosts = connect_to_db(CONST_LOCALHOSTS_DB, "localhosts")
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

        counts["average_threat_score"] = get_average_threat_score()
        counts["ignorelist_count"] = get_row_count(CONST_CONSOLIDATED_DB, "ignorelist")
        
        # Get flow statistics from configuration
        from database.configuration import get_config_settings
        config_dict = get_config_settings()
        
        if config_dict:
            # Get total statistics
            counts["total_packets"] = int(config_dict.get("TotalPackets", "0"))
            counts["total_flows"] = int(config_dict.get("TotalFlows", "0")) 
            counts["total_bytes"] = int(config_dict.get("TotalBytes", "0"))
            
            # Get last batch statistics
            counts["last_packets"] = int(config_dict.get("LastPackets", "0"))
            counts["last_flows"] = int(config_dict.get("LastFlows", "0"))
            counts["last_bytes"] = int(config_dict.get("LastBytes", "0"))
            
            # Get last flow timestamp
            counts["last_flow_seen"] = config_dict.get("LastFlowSeen", None)
            
            # Check system health based on flow data
            try:
                if counts["last_flow_seen"]:
                    last_flow_time = datetime.strptime(counts["last_flow_seen"], '%Y-%m-%d %H:%M:%S')
                    current_time = datetime.now()
                    time_difference = (current_time - last_flow_time).total_seconds()
                    
                    # System is healthy if:
                    # 1. Last flow was seen within the last 5 minutes (300 seconds)
                    # 2. We have non-zero flows and packets in the last batch
                    if (time_difference <= 300):
                        counts["is_healthy"] = "Up"
                        log_info(logger, f"[INFO] System is healthy: Last flow seen {time_difference:.0f} seconds ago")
                    else:
                        log_warn(logger, f"[WARN] System health check failed: Last flow {time_difference:.0f} seconds ago, "
                                f"Flows: {counts['last_flows']}, Packets: {counts['last_packets']}")
            except Exception as e:
                log_error(logger, f"[ERROR] Error checking system health: {e}")
            
            log_info(logger, f"[INFO] Retrieved flow statistics from configuration: "
                     f"Packets: {counts['total_packets']}, Flows: {counts['total_flows']}, "
                     f"Bytes: {counts['total_bytes']}, Last seen: {counts['last_flow_seen']}")
        else:
            log_warn(logger, "[WARN] Could not retrieve configuration for flow statistics")
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error: {e}")
    except ValueError as e:
        log_error(logger, f"[ERROR] Value conversion error for statistics: {e}")
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
        conn = connect_to_db(CONST_CONFIGURATION_DB, "configuration")
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
        conn = connect_to_db(CONST_CONFIGURATION_DB, "configuration")
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
        conn = connect_to_db(CONST_CONFIGURATION_DB, "configuration")
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

def test_database_online(db_path):
    """
    Test if the SQLite database at db_path is online and accessible.

    Args:
        db_path (str): Path to the SQLite database file.

    Returns:
        bool: True if the database is online and a simple query succeeds, False otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        conn.close()
        log_info(logger, f"[INFO] Successfully connected to database: {db_path}")
        return True
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database connection failed: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error during database connection test: {e}")
        return False


def get_p95_execution_times():
    """
    Retrieve the p95 execution time for each function from the dbperformance table.

    Returns:
        dict: A dictionary where keys are function names and values are their p95 execution times.
    """
    logger = logging.getLogger(__name__)
    result = {}
    try:
        conn = connect_to_db(CONST_PERFORMANCE_DB, "dbperformance")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to performance database.")
            return {}

        cursor = conn.cursor()
        query = """
            SELECT function, MIN(execution_time) AS p95_execution_time
            FROM (
                SELECT function,
                       execution_time,
                       ROW_NUMBER() OVER (PARTITION BY function ORDER BY execution_time) AS rn,
                       COUNT(*) OVER (PARTITION BY function) AS total
                FROM dbperformance
            )
            WHERE rn >= CAST(total * 0.95 AS INTEGER)
            GROUP BY function;
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        for function, p95_time in rows:
            result[function] = p95_time

        return result

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving p95 execution times: {e}")
        return {}
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving p95 execution times: {e}")
        return {}
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)