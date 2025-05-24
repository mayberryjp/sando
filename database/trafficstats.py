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


def delete_old_traffic_stats():
    """
    Delete all records from the trafficstats table with a timestamp of 31 days ago or older.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    try:
        # Connect to the consolidated database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "trafficstats")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to trafficstats database.")
            return False

        cursor = conn.cursor()

        config_dict = get_config_settings()
        purge_time_delta = config_dict.get('TrafficStatsPurgeIntervalDays', 31)

        # Calculate the cutoff timestamp (31 days ago)
        cutoff_date = (datetime.now() - timedelta(days=purge_time_delta)).strftime('%Y-%m-%d')

        # Delete records older than the cutoff timestamp
        cursor.execute(f"""
            DELETE FROM trafficstats
            WHERE timestamp LIKE '{cutoff_date}:%'
        """, )

        conn.commit()
        log_info(logger, f"[INFO] Deleted records older than {cutoff_date} from trafficstats table.")
        return True

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while deleting old traffic stats: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while deleting old traffic stats: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def update_traffic_stats(rows, config_dict):
    """
    Update the trafficstats table with hourly traffic statistics for each source IP address.

    Args:
        rows (list): List of tuples containing flow data:
                     (src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_, flow_start, flow_end, last_seen, times_seen, tags)
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db(CONST_CONSOLIDATED_DB, "trafficstats")

    if not conn:
        log_error(logger, "[ERROR] Unable to connect to allflows database.")
        return

    LOCAL_NETWORKS = set(config_dict['LocalNetworks'].split(','))

    try:
        cursor = conn.cursor()

        # Process each row and update the trafficstats table
        for row in rows:
            src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_, flow_start, flow_end, last_seen, times_seen, tags = row

            if not is_ip_in_range(src_ip, LOCAL_NETWORKS):
                continue

            # Format the timestamp as yyyy-mm-dd-hh
            timestamp = datetime.now().strftime('%Y-%m-%d:%H')

            # Insert or update the traffic statistics for the source IP and timestamp
            cursor.execute("""
                INSERT INTO trafficstats (ip_address, timestamp, total_packets, total_bytes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address, timestamp)
                DO UPDATE SET
                    total_packets = total_packets + excluded.total_packets,
                    total_bytes = total_bytes + excluded.total_bytes
            """, (src_ip, timestamp, packets, bytes_))

        conn.commit()
        log_info(logger, f"[INFO] Updated traffic statistics for {len(rows)} rows.")
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error updating traffic statistics: {e}")
    finally:
        disconnect_from_db(conn)
    disconnect_from_db(conn)

def get_traffic_stats_for_ip(ip_address):
    """
    Retrieve all traffic statistics for a specific IP address from the trafficstats table,
    including alert counts for the same timeframes.

    Args:
        ip_address (str): The IP address to filter data by.

    Returns:
        list: A list of dictionaries containing all traffic statistics and alert counts
              for the specified IP address. Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    try:
        # Connect to the consolidated database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "trafficstats")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to trafficstats database.")
            return []

        cursor = conn.cursor()

        # Query to retrieve all traffic data for the specified IP address
        traffic_query = """
            SELECT ip_address, timestamp, total_packets, total_bytes
            FROM trafficstats
            WHERE ip_address = ?
            ORDER BY timestamp DESC
            LIMIT 100
        """
        
        # Use run_timed_query for performance tracking
        traffic_rows, traffic_query_time = run_timed_query(
            cursor,
            traffic_query,
            (ip_address,),
            description=f"get_traffic_stats_for_{ip_address}"
        )
        
        # Query to retrieve alert counts for the same IP address
        alerts_query = """
            SELECT 
                strftime('%Y-%m-%d:%H', last_seen) AS hour,
                COUNT(*) AS alert_count
            FROM 
                alerts
            WHERE 
                datetime(last_seen) >= datetime('now', '-100 hours') AND ip_address = ?
            GROUP BY 
                hour
            ORDER BY 
                hour ASC
        """
        
        # Use run_timed_query for performance tracking
        alert_rows, alerts_query_time = run_timed_query(
            cursor,
            alerts_query,
            (ip_address,),
            description=f"get_alert_counts_for_{ip_address}"
        )
        
        disconnect_from_db(conn)

        # Create a mapping of timestamps to alert counts
        alert_counts = {row[0]: row[1] for row in alert_rows}
        
        # Format the results as a list of dictionaries, including alert counts
        traffic_stats = []
        for row in traffic_rows:
            timestamp = row[1]
            # Get the alert count for this timestamp, or 0 if none exists
            alert_count = alert_counts.get(timestamp, 0)
            
            traffic_stats.append({
                "ip_address": row[0],
                "timestamp": timestamp,
                "total_packets": row[2],
                "total_bytes": row[3],
                "alerts": alert_count
            })

        total_query_time = traffic_query_time + alerts_query_time
        log_info(logger, f"[INFO] Retrieved {len(traffic_stats)} traffic stats entries with alert counts for IP {ip_address} " + 
                         f"in {total_query_time:.2f} ms (traffic: {traffic_query_time:.2f} ms, alerts: {alerts_query_time:.2f} ms)")
        return traffic_stats

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving traffic stats for IP {ip_address}: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving traffic stats for IP {ip_address}: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

