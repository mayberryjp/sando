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
        conn = connect_to_db( "trafficstats")
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
    conn = connect_to_db( "trafficstats")

    if not conn:
        log_error(logger, "[ERROR] Unable to connect to allflows database.")
        return

    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

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

def get_all_ips_traffic_status():
    """
    Retrieve all IP addresses from localhosts and check if they had any traffic in the last 100 hours from trafficstats.
    Returns:
        dict: A dictionary with IP addresses as keys and traffic status as boolean values.
              True if the IP had traffic in the last 100 hours, False otherwise.
    """
    logger = logging.getLogger(__name__)
    ip_traffic_status = {}

    try:
        # Connect to localhosts database to get all IPs
        conn_localhosts = connect_to_db( "localhosts")
        if not conn_localhosts:
            log_error(logger, "[ERROR] Unable to connect to localhosts database.")
            return ip_traffic_status

        cursor_localhosts = conn_localhosts.cursor()
        cursor_localhosts.execute("SELECT DISTINCT ip_address FROM localhosts")
        all_ips = [row[0] for row in cursor_localhosts.fetchall()]
        disconnect_from_db(conn_localhosts)

        # Connect to consolidated database to get active IPs from trafficstats
        conn_trafficstats = connect_to_db( "trafficstats")
        if not conn_trafficstats:
            log_error(logger, "[ERROR] Unable to connect to trafficstats database.")
            return ip_traffic_status

        cursor_trafficstats = conn_trafficstats.cursor()
        recent_traffic_query = """
            SELECT DISTINCT ip_address 
            FROM trafficstats
            WHERE datetime(substr(timestamp, 1, 10) || ' ' || substr(timestamp, 12) || ':00:00') >= datetime('now', '-100 hours')
        """
        cursor_trafficstats.execute(recent_traffic_query)
        active_ips = {row[0] for row in cursor_trafficstats.fetchall()}
        disconnect_from_db(conn_trafficstats)

        # Build the result dictionary - True if IP is in active set, False otherwise
        for ip in all_ips:
            ip_traffic_status[ip] = ip in active_ips

        log_info(logger, f"[INFO] Successfully determined traffic status for {len(ip_traffic_status)} IPs ({len(active_ips)} active)")
        return ip_traffic_status

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error retrieving IP traffic status: {e}")
        return ip_traffic_status
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error retrieving IP traffic status: {e}")
        return ip_traffic_status

def get_traffic_stats_for_ip(ip_address):
    """
    Retrieve traffic statistics for a specific IP address for the last 100 hours,
    including alert counts. Returns data for all hour intervals, even when no data exists.

    Args:
        ip_address (str): The IP address to filter data by.

    Returns:
        list: A list of dictionaries containing traffic statistics for all hour intervals
              in the last 100 hours. Empty intervals will have null values.
    """
    logger = logging.getLogger(__name__)
    try:
        # Connect to the trafficstats database
        conn_traffic = connect_to_db("trafficstats")
        if not conn_traffic:
            log_error(logger, "[ERROR] Unable to connect to trafficstats database.")
            return []

        cursor_traffic = conn_traffic.cursor()

        # Query to retrieve traffic data for the specified IP address within last 100 hours
        traffic_query = """
            SELECT ip_address, timestamp, total_packets, total_bytes
            FROM trafficstats
            WHERE ip_address = ?
            AND datetime(substr(timestamp, 1, 10) || ' ' || substr(timestamp, 12) || ':00:00') >= datetime('now', '-100 hours')
            ORDER BY timestamp DESC
        """
        
        traffic_rows, traffic_query_time = run_timed_query(
            cursor_traffic,
            traffic_query,
            (ip_address,),
            description=f"get_traffic_stats_for_ip_get_traffic_stats"
        )
        disconnect_from_db(conn_traffic)

        # Connect to the alerts database
        conn_alerts = connect_to_db("alerts")
        if not conn_alerts:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return []

        cursor_alerts = conn_alerts.cursor()
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
        
        alert_rows, alerts_query_time = run_timed_query(
            cursor_alerts,
            alerts_query,
            (ip_address,),
            description=f"get_traffic_stats_for_ip_get_alert_counts"
        )
        disconnect_from_db(conn_alerts)

        # Create a mapping of timestamps to traffic data
        traffic_data = {}
        for row in traffic_rows:
            timestamp = row[1]
            traffic_data[timestamp] = {
                "total_packets": row[2],
                "total_bytes": row[3]
            }

        # Create a mapping of timestamps to alert counts
        alert_counts = {row[0]: row[1] for row in alert_rows}
        
        # Generate timestamps for the last 100 hours
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=99)  # 100 hours including current hour
        
        # Format the results as a list of dictionaries for all hour intervals
        traffic_stats = []
        current_time = start_time
        
        while current_time <= end_time:
            timestamp = current_time.strftime('%Y-%m-%d:%H')
            
            # Get traffic data for this timestamp, or use null values if none exists
            traffic_for_hour = traffic_data.get(timestamp)
            
            # Get the alert count for this timestamp, or 0 if none exists
            alert_count = alert_counts.get(timestamp, 0)
            
            traffic_stats.append({
                "ip_address": ip_address,
                "timestamp": timestamp,
                "total_packets": traffic_for_hour["total_packets"] if traffic_for_hour else None,
                "total_bytes": traffic_for_hour["total_bytes"] if traffic_for_hour else None,
                "alerts": alert_count
            })
            
            # Move to the next hour
            current_time += timedelta(hours=1)

        # Sort by timestamp (most recent first)
        traffic_stats.sort(key=lambda x: x["timestamp"], reverse=True)
        
        total_query_time = traffic_query_time + alerts_query_time
        log_info(logger, f"[INFO] Generated {len(traffic_stats)} traffic stats entries (including null entries) " + 
                         f"for IP {ip_address} in {total_query_time:.2f} ms")
        
        return traffic_stats

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving traffic stats for IP {ip_address}: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving traffic stats for IP {ip_address}: {e}")
        return []
    finally:
        if 'conn_traffic' in locals() and conn_traffic:
            disconnect_from_db(conn_traffic)
        if 'conn_alerts' in locals() and conn_alerts:
            disconnect_from_db(conn_alerts)

