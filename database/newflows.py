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


from database.core import connect_to_db, disconnect_from_db


def get_new_flows():
    """
    Retrieve all records from the flows table in the newflows database.

    Returns:
        list: A list of lists containing all flow records,
              or an empty list if an error occurs.
    """
    
    logger = logging.getLogger(__name__)
    conn = None
    
    try:
        # Connect to the newflows database
        conn = connect_to_db( "newflows")
        if not conn:
            log_error(logger, "[ERROR] Failed to connect to newflows database")
            return []
            
        # Execute the query
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM newflows")
        rows = cursor.fetchall()
        
        # Convert tuple rows to lists
        rows = [list(row) for row in rows]
        
        log_info(logger, f"[INFO] Retrieved {len(rows)} flow records from newflows database")
        return rows
        
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to retrieve flows from newflows database: {e}")
        return []
        
    finally:
        # Ensure database connection is closed
        if conn:
            disconnect_from_db(conn)

def update_new_flow(record):
    conn = connect_to_db( "newflows")
    c = conn.cursor()

    c.execute('''
        INSERT INTO newflows (
            src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, flow_start, flow_end, last_seen, times_seen, tags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'), datetime('now', 'localtime'), datetime('now', 'localtime'), 1,?)
        ON CONFLICT(src_ip, dst_ip, src_port, dst_port, protocol)
        DO UPDATE SET 
            packets = packets + excluded.packets,
            bytes = bytes + excluded.bytes,
            flow_end = excluded.flow_end,
            last_seen = excluded.last_seen,
            times_seen = times_seen + 1
    ''', (record['src_ip'], record['dst_ip'], record['src_port'], record['dst_port'],record['protocol'], record['packets'], record['bytes'],  record['tags']))

    conn.commit()
    disconnect_from_db(conn)
