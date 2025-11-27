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

def summarize_alerts_by_ip_last_seen():
    """
    Summarize alerts by IP address over the last 12 hours in one-hour increments.
    Returns results for every hour whether there were alerts or not.

    Returns:
        dict: A dictionary where the main key is the IP address, and the value is another dictionary
            with the key "alert_intervals" containing an array of 12 values representing the count
            of alerts for each one-hour interval, sorted from oldest to most recent.
    """
    logger = logging.getLogger(__name__)
    db_name = CONST_LOCALHOSTS_DB
    conn = connect_to_db(db_name, "alerts")
    if not conn:
        log_error(logger, f"Unable to connect to the database: {db_name}")
        return {"error": "Unable to connect to the database"}

    cursor = conn.cursor()
    intervals = 12

    try:
        # Get the current time and calculate the start time (12 hours ago)
        now = datetime.now()
        start_time = now - timedelta(hours=intervals)

        # First, get all unique IP addresses with alerts in the time period
        ip_query = """
            SELECT DISTINCT ip_address 
            FROM localhosts
        """

        cursor.execute(ip_query)
        all_ips_rows = cursor.fetchall()

        all_ips = [row[0] for row in all_ips_rows]
        
        # Query to fetch alerts within the last 12 hours
        alerts_query = """
            SELECT ip_address, strftime('%Y-%m-%d %H:00:00', last_seen) as hour, COUNT(*)
            FROM alerts
            WHERE last_seen >= ?
            GROUP BY ip_address, hour
            ORDER BY ip_address, hour
        """
        
        alerts_by_hour_rows, alerts_query_time = run_timed_query(
            cursor, 
            alerts_query,
            (start_time.strftime('%Y-%m-%d %H:%M:%S'),),
            description="summarize_alerts_by_ip_last_seen"
        )
        
        disconnect_from_db(conn)

        # Generate all hour intervals for the past 12 hours
        hour_intervals = []
        for i in range(intervals):
            interval_time = now - timedelta(hours=intervals-i-1)
            hour_intervals.append(interval_time.strftime('%Y-%m-%d %H:00:00'))

        # Initialize the result dictionary with all IPs and all hours
        result = {}
        for ip in all_ips:
            result[ip] = {"alert_intervals": [0] * intervals}
            
        # Fill in the actual alert counts where they exist
        for row in alerts_by_hour_rows:
            ip_address = row[0]
            hour = row[1]
            count = row[2]
            
            # Only process IPs that are in our all_ips list (from localhosts)
            if ip_address in all_ips:
                # Find which interval this hour belongs to
                try:
                    hour_index = hour_intervals.index(hour)
                    result[ip_address]["alert_intervals"][hour_index] = count
                except ValueError:
                    # This shouldn't happen if our hour generation is correct
                    log_warn(logger, f"Hour {hour} not found in generated intervals")

        log_info(logger, f"[INFO] Generated alert summary for {len(all_ips)} IPs")
        return result

    except sqlite3.Error as e:
        disconnect_from_db(conn)
        log_error(logger, f"Error summarizing alerts: {e}")
        return {"error": str(e)}
    except Exception as e:
        log_error(logger, f"Unexpected error: {e}")
        return {"error": str(e)}

def summarize_alerts_by_ip():
    """
    Summarize alerts by IP address over the last 12 hours in one-hour increments.
    Returns results for every hour whether there were alerts or not.

    Returns:
        dict: A dictionary where the main key is the IP address, and the value is another dictionary
            with the key "alert_intervals" containing an array of 12 values representing the count
            of alerts for each one-hour interval, sorted from oldest to most recent.
    """
    logger = logging.getLogger(__name__)
    db_name = CONST_LOCALHOSTS_DB
    conn = connect_to_db(db_name, "alerts")
    if not conn:
        log_error(logger, f"Unable to connect to the database: {db_name}")
        return {"error": "Unable to connect to the database"}

    cursor = conn.cursor()
    intervals = 12

    try:
        # Get the current time and calculate the start time (12 hours ago)
        now = datetime.now()
        start_time = now - timedelta(hours=intervals)

        # First, get all unique IP addresses with alerts in the time period
        ip_query = """
            SELECT DISTINCT ip_address 
            FROM localhosts
        """
        
        all_ips_rows, ip_query_time = run_timed_query(
            cursor, 
            ip_query,
            description="summarize_alerts_by_ip_select_distinct_ips"
        )
        
        all_ips = [row[0] for row in all_ips_rows]
        
        # Query to fetch alerts within the last 12 hours
        alerts_query = """
            SELECT ip_address, strftime('%Y-%m-%d %H:00:00', first_seen) as hour, COUNT(*)
            FROM alerts
            WHERE first_seen >= ?
            GROUP BY ip_address, hour
            ORDER BY ip_address, hour
        """
        
        alerts_by_hour_rows, alerts_query_time = run_timed_query(
            cursor, 
            alerts_query,
            (start_time.strftime('%Y-%m-%d %H:%M:%S'),),
            description="summarize_alerts_by_ip"
        )
        
        disconnect_from_db(conn)

        # Generate all hour intervals for the past 12 hours
        hour_intervals = []
        for i in range(intervals):
            interval_time = now - timedelta(hours=intervals-i-1)
            hour_intervals.append(interval_time.strftime('%Y-%m-%d %H:00:00'))

        # Initialize the result dictionary with all IPs and all hours
        result = {}
        for ip in all_ips:
            result[ip] = {"alert_intervals": [0] * intervals}
            
        # Fill in the actual alert counts where they exist
        for row in alerts_by_hour_rows:
            ip_address = row[0]
            hour = row[1]
            count = row[2]
            
            # Only process IPs that are in our all_ips list (from localhosts)
            if ip_address in all_ips:
                # Find which interval this hour belongs to
                try:
                    hour_index = hour_intervals.index(hour)
                    result[ip_address]["alert_intervals"][hour_index] = count
                except ValueError:
                    # This shouldn't happen if our hour generation is correct
                    log_warn(logger, f"Hour {hour} not found in generated intervals")

        total_time = ip_query_time + alerts_query_time
        log_info(logger, f"[INFO] Generated alert summary for {len(all_ips)} IPs in {total_time:.2f} ms " +
                         f"(IP query: {ip_query_time:.2f} ms, Alerts query: {alerts_query_time:.2f} ms)")
        return result

    except sqlite3.Error as e:
        disconnect_from_db(conn)
        log_error(logger, f"Error summarizing alerts: {e}")
        return {"error": str(e)}
    except Exception as e:
        log_error(logger, f"Unexpected error: {e}")
        return {"error": str(e)}

def get_hourly_alerts_summary(ip_address, start_time=None):
    """
    Get a summary of alerts by hour for a specific IP address.
    
    Args:
        ip_address (str): The IP address to filter alerts by
        start_time (str, optional): The timestamp to start from in ISO format 
                                  (e.g., '2023-05-01 00:00:00').
                                  If not provided, retrieves all alerts.
        
    Returns:
        list: A list of tuples containing (hour, count) for each hour,
              where hour is in format 'YYYY-MM-DD HH:00:00' and count is the number of alerts.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the alerts database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return []

        cursor = conn.cursor()
        
        # If no start_time provided, use a very old date to get all alerts
        if not start_time:
            start_time = '2000-01-01 00:00:00'
        
        # Get hourly summary of alerts using run_timed_query
        hourly_query = """
            SELECT strftime('%Y-%m-%d %H:00:00', first_seen) as hour, COUNT(*)
            FROM alerts
            WHERE ip_address = ? AND first_seen >= ?
            GROUP BY hour
            ORDER BY hour
        """
        
        hourly_summary, query_time = run_timed_query(
            cursor, 
            hourly_query, 
            (ip_address, start_time),
            description=f"get_hourly_alerts_summary"
        )
        
        log_info(logger, f"[INFO] Retrieved {len(hourly_summary)} hourly alert entries for IP {ip_address} in {query_time:.2f} ms")
        return hourly_summary
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving hourly alert summary: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving hourly alert summary: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_all_alerts_by_ip(ip_address):
    """
    Retrieve all alerts for a specific IP address from the alerts table.

    Args:
        ip_address (str): The IP address to filter alerts by.

    Returns:
        list: A list of dictionaries containing all alerts for the specified IP,
              ordered by last_seen timestamp in descending order.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the alerts database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return []

        cursor = conn.cursor()
        
        # Retrieve all alerts for the specified IP address, most recent first
        alerts_query = """
            SELECT id, ip_address, flow, category, 
                alert_enrichment_1, alert_enrichment_2,
                times_seen, first_seen, last_seen, acknowledged
            FROM alerts 
            WHERE ip_address = ?
            ORDER BY last_seen DESC
        """
        
        rows, query_time = run_timed_query(
            cursor, 
            alerts_query, 
            (ip_address,),
            description=f"get_all_alerts_for_ip"
        )
        
        # Get column names from cursor description
        columns = [column[0] for column in cursor.description]
        
        # Format the results as a list of dictionaries
        alerts = []
        for row in rows:
            alert_dict = dict(zip(columns, row))
            # Parse JSON if flow is stored as a string
            if 'flow' in alert_dict and isinstance(alert_dict['flow'], str):
                try:
                    alert_dict['flow'] = json.loads(alert_dict['flow'])
                except:
                    pass  # Keep as string if JSON parsing fails
            alerts.append(alert_dict)

        log_info(logger, f"[INFO] Retrieved {len(alerts)} alerts for IP address {ip_address} in {query_time:.2f} ms")
        return alerts
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving alerts for IP {ip_address}: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving alerts for IP {ip_address}: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_alert_count_by_id(alert_id):
    """
    Get the count of alerts with the specified ID in the database.
    
    Args:
        alert_id (str): The ID of the alert to count
        
    Returns:
        int: The count of matching alerts, or 0 if not found or an error occurs
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the alerts database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return 0

        cursor = conn.cursor()
        
        # Count alerts with the specified ID using direct cursor execution
        count_query = "SELECT COUNT(*) FROM alerts WHERE id = ?"
        cursor.execute(count_query, (alert_id,))
        
        # Get the count from the first row, first column of the result
        count = cursor.fetchone()[0]
        
        return count
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while counting alerts with ID {alert_id}: {e}")
        return 0
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while counting alerts with ID {alert_id}: {e}")
        return 0
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_recent_alerts_database():
    """
    Retrieve the most recent 100 alerts from the alerts table.

    Returns:
        list: A list of dictionaries containing the most recent 100 alerts,
              ordered by last_seen timestamp in descending order.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the alerts database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return []

        cursor = conn.cursor()
        
        # Retrieve the most recent alerts, limited to 100
        recent_alerts_query = """
            SELECT id, ip_address, flow, category, 
                alert_enrichment_1, alert_enrichment_2,
                times_seen, first_seen, last_seen, acknowledged
            FROM alerts 
            ORDER BY first_seen DESC 
            LIMIT 100
        """
        
        rows, query_time = run_timed_query(
            cursor, 
            recent_alerts_query,
            description="get_recent_alerts_database"
        )
        
        log_info(logger, f"[INFO] Retrieved {len(rows)} recent alerts in {query_time:.2f} ms")
        return rows

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving recent alerts: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving recent alerts: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def delete_alert_database(alert_id):
    """
    Delete an alert from the database.
    
    Args:
        alert_id (str): The ID of the alert to delete
        
    Returns:
        bool: True if the deletion was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the alerts database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return False

        cursor = conn.cursor()
        
        # Delete the alert
        cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
        
        # Check if any rows were affected
        if cursor.rowcount > 0:
            conn.commit()
            log_info(logger, f"[INFO] Alert with ID {alert_id} was successfully deleted.")
            return True
        else:
            log_warn(logger, f"[WARN] No alert found with ID {alert_id} to delete.")
            return False

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while deleting alert {alert_id}: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while deleting alert {alert_id}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def log_alert_to_db(ip_address, flow, category, alert_enrichment_1, alert_enrichment_2, alert_id_hash, realert=False):
    """
    Logs an alert to the alerts.db SQLite database and indicates whether it was an insert or an update.

    Args:
        ip_address (str): The IP address associated with the alert.
        flow (dict): The flow data as a dictionary.
        category (str): The category of the alert.
        alert_enrichment_1 (str): Additional enrichment data for the alert.
        alert_enrichment_2 (str): Additional enrichment data for the alert.
        alert_id_hash (str): A unique hash for the alert.
        realert (bool): Whether this is a re-alert.

    Returns:
        str: "insert" if a new row was inserted, "update" if an existing row was updated, or "error" if an error occurred.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return "error"

        cursor = conn.cursor()

        # Execute the insert or update query
        cursor.execute("""
            INSERT INTO alerts (id, ip_address, flow, category, alert_enrichment_1, alert_enrichment_2, times_seen, first_seen, last_seen, acknowledged)
            VALUES (?, ?, ?, ?, ?, ?, 1, datetime('now', 'localtime'), datetime('now', 'localtime'), 0)
            ON CONFLICT(id)
            DO UPDATE SET
                times_seen = times_seen + 1,
                last_seen = datetime('now', 'localtime')
        """, (alert_id_hash, ip_address, json.dumps(flow), category, alert_enrichment_1, alert_enrichment_2))

        # Check the number of rows affected
        if conn.total_changes == 1:
            operation = "insert"
            log_info(logger, f"[INFO] Alert logged to database for IP: {ip_address}, Category: {category} ({operation}).")
        else:
            operation = "update"

        conn.commit()
        
        return operation

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error logging alert to database: {e}")
        return "error"
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_alerts_summary():
    """
    Get a summary of alerts by category from alerts.db.
    Prints total count and breakdown by category.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database")
            return

        cursor = conn.cursor()
        
        # Get total count using run_timed_query
        total_count_query = "SELECT COUNT(*) FROM alerts"
        total_count_result, count_query_time = run_timed_query(
            cursor, 
            total_count_query,
            description="get_alerts_summary_count"
        )
        total_count = total_count_result[0][0]
        
        # Get counts by category using run_timed_query
        category_count_query = """
            SELECT category, COUNT(*) as count 
            FROM alerts 
            GROUP BY category 
            ORDER BY count DESC
        """
        
        categories, category_query_time = run_timed_query(
            cursor, 
            category_count_query,
            description="get_alerts_summary_alerts_by_category"
        )
        
        # Log the summary with performance metrics
        log_info(logger, f"[INFO] Total alerts: {total_count} (query took {count_query_time:.2f} ms)")
        log_info(logger, f"[INFO] Breakdown by category (query took {category_query_time:.2f} ms):")
        for category, count in categories:
            percentage = (count / total_count * 100) if total_count > 0 else 0
            log_info(logger, f"[INFO]   {category}: {count} ({percentage:.1f}%)")

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error getting alerts summary: {e}")
    finally:
        if 'conn' in locals():
            disconnect_from_db(conn)

def get_recent_alerts_by_ip(ip_address):
    """
    Retrieve the most recent 100 alerts for a specific IP address from the alerts table.

    Args:
        ip_address (str): The IP address to filter alerts by.

    Returns:
        list: A list of dictionaries containing the most recent 100 alerts for the specified IP.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the alerts database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return []

        cursor = conn.cursor()
        
        # Retrieve alerts for the specified IP address, most recent first, limited to 100
        alerts_query = """
            SELECT id, ip_address, flow, category, 
                   alert_enrichment_1, alert_enrichment_2,
                   times_seen, first_seen, last_seen, acknowledged
            FROM alerts 
            WHERE ip_address = ?
            ORDER BY first_seen DESC 
            LIMIT 100
        """
        
        rows, query_time = run_timed_query(
            cursor, 
            alerts_query, 
            (ip_address,),
            description=f"get_recent_alerts_by_ip"
        )
        
        # Get column names from cursor description
        columns = [column[0] for column in cursor.description]
        
        # Format the results as a list of dictionaries
        alerts = []
        for row in rows:
            alert_dict = dict(zip(columns, row))
            # Parse JSON if flow is stored as a string
            if 'flow' in alert_dict and isinstance(alert_dict['flow'], str):
                try:
                    alert_dict['flow'] = json.loads(alert_dict['flow'])
                except:
                    pass  # Keep as string if JSON parsing fails
            alerts.append(alert_dict)

        log_info(logger, f"[INFO] Retrieved {len(alerts)} recent alerts for IP address {ip_address} in {query_time:.2f} ms")
        return alerts

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving alerts for IP {ip_address}: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving alerts for IP {ip_address}: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_all_alerts():
    """
    Retrieve all records from the alerts table.

    Returns:
        list: A list of dictionaries containing all records from the alerts table.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return []

        cursor = conn.cursor()
        
        # Use run_timed_query for the SELECT operation
        rows, query_time = run_timed_query(
            cursor,
            "SELECT * FROM alerts",
            description="get_all_alerts"
        )

        # Get column names from cursor description
        columns = [column[0] for column in cursor.description]
        
        # Format the results as a list of dictionaries
        alerts = []
        for row in rows:
            alert_dict = dict(zip(columns, row))
            # Parse JSON if flow is stored as a string
            if 'flow' in alert_dict and isinstance(alert_dict['flow'], str):
                try:
                    alert_dict['flow'] = json.loads(alert_dict['flow'])
                except:
                    pass  # Keep as string if JSON parsing fails
            alerts.append(alert_dict)

        log_info(logger, f"[INFO] Retrieved {len(alerts)} alerts from the database in {query_time:.2f} ms")
        return alerts

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving alerts: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving alerts: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_alerts_by_category(category_name):
    """
    Retrieve alerts from the database for a specific category.

    Args:
        category_name (str): The category name to filter alerts by

    Returns:
        list: A list of raw database rows for the specified category.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the alerts database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return []

        cursor = conn.cursor()
        
        # Retrieve all alerts for the specified category using run_timed_query
        category_query = """
            SELECT id, ip_address, flow, category, alert_enrichment_1, alert_enrichment_2, 
                   times_seen, first_seen, last_seen, acknowledged
            FROM alerts
            WHERE category = ?
            ORDER BY last_seen DESC
        """
        
        rows, query_time = run_timed_query(
            cursor, 
            category_query, 
            (category_name,),
            description=f"get_alerts_by_category"
        )
        
        log_info(logger, f"[INFO] Retrieved {len(rows)} alerts for category '{category_name}' in {query_time:.2f} ms")
        return rows

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving alerts for category '{category_name}': {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving alerts for category '{category_name}': {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def update_alert_acknowledgment(alert_id, acknowledged):
    """
    Update the acknowledged status of an alert in the database.
    
    Args:
        alert_id (str): The ID of the alert to update
        acknowledged (int): 1 for acknowledged, 0 for not acknowledged
        
    Returns:
        bool: True if the update was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the alerts database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return False

        cursor = conn.cursor()
        
        # Update the acknowledged flag
        cursor.execute("UPDATE alerts SET acknowledged = ? WHERE id = ?", (acknowledged, alert_id))
        
        # Check if any rows were affected
        if cursor.rowcount > 0:
            conn.commit()
            log_info(logger, f"[INFO] Alert {alert_id} acknowledged status updated to {acknowledged}.")
            return True
        else:
            log_warn(logger, f"[WARN] No alert found with ID {alert_id}.")
            return False

    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while updating alert acknowledgment: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while updating alert acknowledgment: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_all_alerts_by_category(category):
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to alerts database")
            return []
            
        cursor = conn.cursor()
        
        # Convert this query to use run_timed_query
        rows, query_time = run_timed_query(
            cursor,
            """
            SELECT id, ip_address, flow, category, 
                alert_enrichment_1, alert_enrichment_2,
                times_seen, first_seen, last_seen, acknowledged
            FROM alerts 
            WHERE category = ?
            ORDER BY last_seen DESC
            """,
            (category,),
            description=f"get_all_alerts_by_category"
        )
        
        # Process the results as before
        columns = [column[0] for column in cursor.description]
        alerts = [dict(zip(columns, row)) for row in rows]
        
        log_info(logger, f"[INFO] Retrieved {len(alerts)} alerts for category {category} in {query_time:.2f} ms")
        return alerts
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def delete_ignorelisted_alerts(ignorelist_id, src_ip, dst_ip, dst_port, protocol):
    """
    Delete alerts that match the ignorelist criteria from the database using direct JSON extraction.
    Supports wildcards (*) for any of the filtering parameters.
    
    Args:
        ignorelist_id (str): The ID of the ignorelist entry
        src_ip (str): Source IP address to match, or "*" for any
        dst_ip (str): Destination IP address to match, or "*" for any
        dst_port (str): Destination port to match, or "*" for any
        protocol (str): Protocol to match, or "*" for any
        
    Returns:
        int: The number of deleted alerts
    """
    logger = logging.getLogger(__name__)
    alerts_deleted = 0
    try:
        # Connect to alerts database
        conn_alerts = connect_to_db(CONST_CONSOLIDATED_DB, "alerts")
        if not conn_alerts:
            log_error(logger, "[ERROR] Unable to connect to alerts database.")
            return alerts_deleted
            
        cursor_alerts = conn_alerts.cursor()
        
        # Build the WHERE conditions dynamically, handling wildcards
        where_conditions = ["1=1"]  # Always true condition to start with
        params = []
        
        # Source IP condition
        if src_ip != "*":
            where_conditions.append("ip_address = ?")
            params.append(src_ip)
        else:
            where_conditions.append("ip_address = ?")
            params.append(dst_ip)
        
        # Destination IP condition
        if dst_ip != "*":
            where_conditions.append("(json_extract(flow, '$[0]') = ? OR json_extract(flow, '$[1]') = ?)")
            params.extend([dst_ip, dst_ip])
        
        # Destination port condition
        if dst_port != "*":
            where_conditions.append("(CAST(json_extract(flow, '$[2]') AS TEXT) = ? OR CAST(json_extract(flow, '$[3]') AS TEXT) = ?)")
            params.extend([str(dst_port), str(dst_port)]) 
        
        # Protocol condition
        if protocol != "*":
            where_conditions.append("CAST(json_extract(flow, '$[4]') AS TEXT) = ?")
            params.append(protocol)
        
        # Create the DELETE query with direct JSON extraction
        query = f"""
            DELETE FROM alerts
            WHERE {' AND '.join(where_conditions)}
        """
        
        log_info(logger, f"[INFO] Executing alert deletion for ignorelist entry {query} and params {params}")
        log_info(logger, f"[INFO] Filter criteria: src_ip={src_ip}, dst_ip={dst_ip}, dst_port={dst_port}, protocol={protocol}")
        log_info(logger, f"[INFO] Query: {query}")
        
        # Execute the DELETE query with parameters
        cursor_alerts.execute(query, params)
        alerts_deleted = cursor_alerts.rowcount
        conn_alerts.commit()
        
        log_info(logger, f"[INFO] Applied ignorelist entry {ignorelist_id}: Deleted {alerts_deleted} alerts")
        return alerts_deleted
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while applying ignorelist entry {ignorelist_id}: {e}")
        return 0
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while applying ignorelist entry {ignorelist_id}: {e}")
        return 0
    finally:
        if 'conn_alerts' in locals() and conn_alerts:
            disconnect_from_db(conn_alerts)