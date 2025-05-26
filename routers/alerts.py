import sys
import os
from pathlib import Path
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
sys.path.insert(0, parent_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
from bottle import Bottle, request, response, hook, route
import logging
from init import *
app = Bottle()

def setup_alerts_routes(app):

    @app.route('/api/alerts/ip/<ip_address>', method=['DELETE'])
    def delete_alerts_for_ip(ip_address):
        """
        API endpoint to delete all alerts for a specific IP address.
        
        Args:
            ip_address: The IP address for which all alerts should be deleted.
            
        Returns:
            JSON object indicating success or failure and the count of deleted alerts.
        """
        logger = logging.getLogger(__name__)
        
        try:
            # Import the delete function
            from database.alerts import delete_alerts_by_ip
            
            # Delete all alerts for the specified IP address
            success, count = delete_alerts_by_ip(ip_address)
            
            response.content_type = 'application/json'
            
            if success:
                log_info(logger, f"[INFO] Successfully deleted {count} alerts for IP address: {ip_address}")
                return {
                    "success": True,
                    "message": f"Successfully deleted {count} alerts for IP address: {ip_address}",
                    "count": count
                }
            else:
                log_error(logger, f"[ERROR] Failed to delete alerts for IP address: {ip_address}")
                response.status = 500
                return {
                    "success": False,
                    "error": f"Failed to delete alerts for IP address: {ip_address}"
                }
            
        except Exception as e:
            log_error(logger, f"[ERROR] Error deleting alerts for IP address {ip_address}: {e}")
            response.status = 500
            return {"success": False, "error": str(e)}

    @app.route('/api/alerts/category/<category_name>', method=['GET'])
    def get_alerts_by_category_api(category_name):
        """
        API endpoint to get alerts for a specific category.
        
        Args:
            category_name: The category name to filter alerts by.
        
        Returns:
            JSON object containing all alerts for the specified category.
        """
        logger = logging.getLogger(__name__)
        
        try:
            # Import the function from database.py
            from database.alerts import get_alerts_by_category
            
            # Get alerts by category
            alerts = get_alerts_by_category(category_name)
            
            if not alerts:
                log_info(logger, f"[INFO] No alerts found for category: {category_name}")
                return json.dumps([])
            
            # Get all localhost information
            localhosts = get_localhosts_all()
            
            # Create a lookup dictionary for faster access to local descriptions
            localhost_descriptions = {}
            for localhost in localhosts:
                ip = localhost.get("ip_address")
                if ip:
                    localhost_descriptions[ip] = localhost.get("local_description", "")

            # Format the response
            formatted_alerts = [{
                "id": row[0],
                "ip_address": row[1],
                "category": row[3],
                "alert_enrichment_1": row[4],
                "alert_enrichment_2": row[5],
                "times_seen": row[6],
                "first_seen": row[7],
                "last_seen": row[8],
                "acknowledged": bool(row[9]),
                "local_description": localhost_descriptions.get(row[1], "")
            } for row in alerts]
            
            response.content_type = 'application/json'
            log_info(logger, f"[INFO] Retrieved {len(alerts)} alerts for category {category_name}")
            return json.dumps(formatted_alerts, indent=2)
            
        except sqlite3.Error as e:
            log_error(logger, f"[ERROR] Database error fetching alerts for category {category_name}: {e}")
            response.status = 500
            return {"error": str(e)}
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to get alerts for category {category_name}: {e}")
            response.status = 500
            return {"error": str(e)}

    # API for CONST_CONSOLIDATED_DB
    @app.route('/api/alerts', method=['GET'])
    def alerts():
        """
        API endpoint to get all alerts.

        Returns:
            JSON array containing all alerts.
        """
        logger = logging.getLogger(__name__)
        
        if request.method == 'GET':
            try:
                # Use the database function to get all alerts
                all_alerts = get_all_alerts()
                
                if not all_alerts:
                    log_warn(logger, "[WARN] No alerts found in the database")
                    response.content_type = 'application/json'
                    return json.dumps([])
                
                # Format the response to match the expected structure
                formatted_alerts = []
                for alert in all_alerts:
                    formatted_alert = {
                        "id": alert.get("id"),
                        "ip_address": alert.get("ip_address"),
                        "category": alert.get("category"),
                        "alert_enrichment_1": alert.get("enrichment_1"),
                        "alert_enrichment_2": alert.get("enrichment_2"),
                        "times_seen": alert.get("times_seen"),
                        "first_seen": alert.get("first_seen"),
                        "last_seen": alert.get("last_seen"),
                        "acknowledged": alert.get("acknowledged")
                    }
                    formatted_alerts.append(formatted_alert)
                
                response.content_type = 'application/json'
                log_info(logger, f"[INFO] Fetched {len(formatted_alerts)} alerts successfully")
                return json.dumps(formatted_alerts)
                
            except Exception as e:
                log_error(logger, f"[ERROR] Failed to fetch alerts: {e}")
                response.status = 500
                return {"error": str(e)}


    @app.route('/api/alerts/<id>', method=['PUT'])
    def modify_alert(id):
        logger = logging.getLogger(__name__)

        if request.method == 'PUT':
            # Update an alert
            data = request.json
            acknowledged = data.get('acknowledged')
    
            try:
                update_alert_acknowledgment(id, acknowledged)

                response.content_type = 'application/json'
                log_info(logger, f"Updated alert: {id}")
                return {"message": "Alert updated successfully"}
            except sqlite3.Error as e:
                log_error(logger, f"Error updating alert: {e}")
                response.status = 500
                return {"error": str(e)}

    @app.route('/api/alerts/<id>', method=['DELETE'])
    def delete_alert(id):
        """
        API endpoint to delete an alert by its ID.

        Args:
            id: The ID of the alert to delete.

        Returns:
            JSON object indicating success or failure.
        """
        logger = logging.getLogger(__name__)

        delete_alert_database(id)

        response.content_type = 'application/json'
        log_info(logger, f"[INFO] Deleted alert with ID: {id}")
        return {"message": f"Alert with ID {id} deleted successfully"}


    @app.route('/api/alerts/summary', method=['GET'])
    def summarize_alerts():
        """
        API endpoint to summarize alerts by IP address over the last 12 hours in one-hour increments.
        """
        logger = logging.getLogger(__name__)
        try:
            summary = summarize_alerts_by_ip()
            response.content_type = 'application/json'
            #log_info(logger, "[INFO] Summarized alerts successfully.")
            return json.dumps(summary)
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to summarize alerts: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route('/api/alerts/recent/<ip_address>', method=['GET'])
    def get_recent_alerts_by_ip_api(ip_address):
        """
        API endpoint to get the most recent alerts for a specific IP address.
        Returns alerts sorted by last_seen timestamp in descending order.

        Args:
            ip_address: The IP address to filter alerts by.

        Returns:
            JSON object containing the most recent alerts for the specified IP address.
        """
        logger = logging.getLogger(__name__)
        
        try:
            # Use the database function to get recent alerts
            alerts = get_recent_alerts_by_ip(ip_address)
            
            if not alerts:
                log_info(logger, f"[INFO] No recent alerts found for IP address: {ip_address}")
                response.content_type = 'application/json'
                return json.dumps([])
            
            # Get all localhost information for local descriptions
            localhosts = get_localhosts_all()
            
            # Create a lookup dictionary for faster access to local descriptions
            localhost_descriptions = {}
            for localhost in localhosts:
                ip = localhost.get("ip_address")
                if ip:
                    localhost_descriptions[ip] = localhost.get("local_description", "")
            
            # Add local description to each alert
            for alert in alerts:
                alert["local_description"] = localhost_descriptions.get(alert.get("ip_address"), "")
            
            response.content_type = 'application/json'
            log_info(logger, f"[INFO] Retrieved {len(alerts)} recent alerts for IP address {ip_address}")
            return json.dumps(alerts, indent=2)
            
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to get recent alerts for IP {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route('/api/alerts/summary/<ip_address>', method=['GET'])
    def summarize_alerts_by_ip_address(ip_address):
        """
        API endpoint to summarize recent alerts for a specific IP address.

        Args:
            ip_address: The IP address to filter alerts by.

        Returns:
            JSON object containing a summary of alerts for the specified IP address.
        """
        logger = logging.getLogger(__name__)

        try:
            # Query to fetch alerts for the specified IP address within the last 12 hours
            intervals = 48
            now = datetime.now()
            start_time = now - timedelta(hours=intervals)
            rows = get_hourly_alerts_summary(ip_address,start_time.strftime('%Y-%m-%d %H:%M:%S') )

            # Initialize the result dictionary
            result = {"ip_address": ip_address, "alert_intervals": [0] * intervals}

            # Process the rows to build the summary
            for row in rows:
                hour = datetime.strptime(row[0], '%Y-%m-%d %H:00:00')
                count = row[1]

                # Calculate the index for the hour interval
                hour_diff = int((now - hour).total_seconds() // 3600)
                if 0 <= hour_diff < intervals:
                    # Reverse the index to place the most recent at the last position
                    result["alert_intervals"][intervals - 1 - hour_diff] = count

            response.content_type = 'application/json'
            log_info(logger, f"[INFO] Summarized alerts for IP address {ip_address}")
            return json.dumps(result, indent=2)

        except sqlite3.Error as e:
            log_error(logger, f"[ERROR] Database error summarizing alerts for IP {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to summarize alerts for IP {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}


    @app.route('/api/alerts/recent', method=['GET'])
    def get_recent_alerts():
        """
        API endpoint to get the 100 most recent alerts.
        Returns alerts sorted by last_seen timestamp in descending order.
        """
        logger = logging.getLogger(__name__)


        # Get all localhost information
        localhosts = get_localhosts_all()
        
        # Create a lookup dictionary for faster access to local descriptions
        localhost_descriptions = {}
        for localhost in localhosts:
            ip = localhost.get("ip_address")
            if ip:
                localhost_descriptions[ip] = localhost.get("local_description", "")

        rows = get_recent_alerts_database()
            
        # Format the response
        alerts = [{
            "id": row[0],
            "ip_address": row[1],
            "flow": row[2],
            "category": row[3],
            "alert_enrichment_1": row[4],
            "alert_enrichment_2": row[5],
            "times_seen": row[6],
            "first_seen": row[7],
            "last_seen": row[8],
            "acknowledged": bool(row[9]),
            "local_description": localhost_descriptions.get(row[1], "")
        } for row in rows]
            
        response.content_type = 'application/json'
        log_info(logger, f"[INFO] Retrieved {len(alerts)} recent alerts")
        return json.dumps(alerts, indent=2)


    @app.route('/api/alerts/<ip_address>', method=['GET'])
    def get_alerts_by_ip(ip_address):
        """
        API endpoint to get alerts for a specific IP address.
        
        Args:
            ip_address: The IP address to filter alerts by.
        
        Returns:
            JSON object containing all alerts for the specified IP address.
        """
        logger = logging.getLogger(__name__)

        # Get all localhost information
        localhosts = get_localhosts_all()
        
        # Create a lookup dictionary for faster access to local descriptions
        localhost_descriptions = {}
        for localhost in localhosts:
            ip = localhost.get("ip_address")
            if ip:
                localhost_descriptions[ip] = localhost.get("local_description", "")
                
        try:
            rows = get_all_alerts_by_ip(ip_address)
            # Fetch alerts for the specified IP address
            
            # Format the response
            alerts = [{
                "id": row[0],
                "ip_address": row[1],
                "flow": row[2],
                "category": row[3],
                "alert_enrichment_1": row[4],
                "alert_enrichment_2": row[5],
                "times_seen": row[6],
                "first_seen": row[7],
                "last_seen": row[8],
                "acknowledged": bool(row[9]),
                "local_description": localhost_descriptions.get(row[1], "")
            } for row in rows]
            
            response.content_type = 'application/json'
            log_info(logger, f"[INFO] Retrieved {len(alerts)} alerts for IP address {ip_address}")
            return json.dumps(alerts, indent=2)
            
        except sqlite3.Error as e:
            log_error(logger, f"[ERROR] Database error fetching alerts for IP {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to get alerts for IP {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}
        
    @app.route('/api/alerts/all', method=['DELETE'])
    def delete_all_alerts():
        """
        API endpoint to delete all alerts from the database.

        Returns:
            JSON object indicating success or failure.
        """
        logger = logging.getLogger(__name__)
        
        try:
            # Import or use the database function
            from database.core import delete_all_records            
            # Delete all alerts
            count = delete_all_records(CONST_CONSOLIDATED_DB, "alerts")
            
            response.content_type = 'application/json'

            return {"message": f"All alerts deleted successfully records)"}
            
        except sqlite3.Error as e:
            log_error(logger, f"[ERROR] Database error when deleting all alerts: {e}")
            response.status = 500
            return {"error": str(e)}
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to delete all alerts: {e}")
            response.status = 500
            return {"error": str(e)}