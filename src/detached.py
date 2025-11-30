import sqlite3
from src.const import CONST_ACTIONS_DB, CONST_CONFIGURATION_DB

def get_config_settings_detached():
    """Read configuration settings from the configuration database into a dictionary."""

    try:
        conn = connect_to_db_detached(CONST_CONFIGURATION_DB)
        if not conn:
            return None
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM configuration")
        config_dict = dict(cursor.fetchall())
        conn.close()
        return config_dict
    except sqlite3.Error as e:
        return None
    
def connect_to_db_detached(DB_NAME):
    """Establish a connection to the specified database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        return conn
    except sqlite3.Error as e:
        return None
    

def insert_action_detached(action_text):
    """
    Insert a new record into the actions table.

    Args:
        action_data (dict): A dictionary containing the action data to insert.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    try:
        conn = connect_to_db_detached(CONST_ACTIONS_DB)

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO actions (action_text, acknowledged)
            VALUES (?, 0)
        """, (action_text,))
        conn.commit()
        conn.close()
        return True

    except sqlite3.Error as e:
        print(f"Error inserting action: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            conn.close()

