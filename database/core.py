import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
import time
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
from locallogging import log_info, log_error

def delete_database(db_path):
    """Deletes the specified SQLite database file if it exists."""
    logger = logging.getLogger(__name__)
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
            log_info(logger, f"[INFO] Deleted: {db_path}")
        else:
            log_info(logger, f"[INFO] {db_path} does not exist, skipping deletion.")
    except Exception as e:
        log_error(logger,f"[ERROR] Error deleting {db_path}: {e}")

def connect_to_db(DB_NAME,table):
    """Establish a connection to the specified database."""
    logger = logging.getLogger(__name__)

    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute("PRAGMA busy_timeout = 10000")
        #log_info(logger, f"[INFO] Connected to database: {DB_NAME} table {table}")
        return conn
    except sqlite3.Error as e:
        log_error(logger,f"[ERROR] Error connecting to database {DB_NAME} table {table}: {e}")
        return None

def disconnect_from_db(conn):
    """
    Safely close the database connection.

    Args:
        conn: The SQLite connection object to close.
    """
    logger = logging.getLogger(__name__)
    try:
        if conn:
            conn.close()
            #log_info(logger, "[INFO] Database connection closed successfully.")
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error closing database connection: {e}")
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while closing database connection: {e}")

def create_table(db_name, create_table_sql, table):
    """Initializes a SQLite database with the specified schema."""
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(db_name, table)
        if not conn:
            log_error(logger,f"[ERROR] Unable to connect to {db_name}")
            return

        cursor = conn.cursor()
        cursor.executescript(create_table_sql)
        conn.commit()
        log_info(logger, f"[INFO] {db_name} table {table} initialized successfully.")
        disconnect_from_db(conn)
    except sqlite3.Error as e:
        log_error(logger,f"[ERROR] Error initializing {db_name}: {e}")

def delete_all_records(db_name, table_name):
    """Delete all records from the specified database and table."""
    logger = logging.getLogger(__name__)
    conn = connect_to_db(db_name, table_name)
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(f"DELETE FROM {table_name}")
            conn.commit()
            log_info(logger, f"[INFO] All records deleted from {db_name} {table_name}")
        except sqlite3.Error as e:
            log_error(logger,f"[ERROR] Error deleting records from {db_name} {table_name}: {e}")
        finally:
            disconnect_from_db(conn)
    disconnect_from_db(conn)

def get_row_count(db_name, table_name):
    """
    Get the total number of rows in a specified database table.
    
    Args:
        db_name (str): The database file path
        table_name (str): The table name to count rows from
        
    Returns:
        int: Number of rows in the table, or -1 if there's an error
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(db_name, table_name)
        if not conn:
            log_error(logger, f"[ERROR] Unable to connect to database {db_name}")
            return -1

        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
    
        return count

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error counting rows in {db_name}.{table_name}: {e}")
        return -1
    finally:
        if 'conn' in locals():
            disconnect_from_db(conn)

def run_timed_query(cursor, query, params=None, description=None, fetch_all=True):
    """
    Execute a database query and time its execution.
    
    Args:
        cursor: The database cursor
        query: The SQL query string
        params: Parameters for the query (optional)
        description: Description of the query (optional)
        fetch_all: Whether to fetch all results (default True)
        
    Returns:
        tuple: (results, execution_time_ms) or (rowcount, execution_time_ms) for non-SELECT queries
    """
    logger = logging.getLogger(__name__)
    desc = description or query.split()[0:3]  # Use first few words of query if no description
    
    start_time = time.time()
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)
    
    if fetch_all:
        results = cursor.fetchall()
        execution_time = (time.time() - start_time) * 1000
        log_info(logger, f"[PERFORMANCE] Query '{desc}' returned {len(results)} rows in {execution_time:.2f} ms")
        return results, execution_time
    else:
        rowcount = cursor.rowcount
        execution_time = (time.time() - start_time) * 1000
        log_info(logger, f"[PERFORMANCE] Query '{desc}' affected {rowcount} rows in {execution_time:.2f} ms")
        return rowcount, execution_time
    
def delete_table(db_name, table_name):
    """
    Delete (drop) a table from the specified SQLite database.

    Args:
        db_name (str): The database file path.
        table_name (str): The name of the table to drop.

    Returns:
        bool: True if the table was deleted successfully, False otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(db_name, table_name)
        if not conn:
            log_error(logger, f"[ERROR] Unable to connect to database {db_name}")
            return False

        cursor = conn.cursor()
        cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
        conn.commit()
        log_info(logger, f"[INFO] Table '{table_name}' deleted from {db_name}")
        return True
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error deleting table {table_name} from {db_name}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)