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

def setup_trafficstats_routes(app):


    @app.route('/api/trafficstatus', method=['GET'])
    def get_all_ips_traffic_status_route():
        """
        API endpoint to get traffic status for all IP addresses.
        Returns a mapping of IP addresses to boolean values indicating
        if they had traffic in the last 100 hours.
    
        Returns:
            JSON object containing IP addresses as keys and boolean traffic status as values.
        """
        logger = logging.getLogger(__name__)
        try:
            # Call the function to get traffic status for all IPs
            ip_traffic_status = get_all_ips_traffic_status()
            
            response.content_type = 'application/json'
            active_count = sum(1 for status in ip_traffic_status.values() if status)
            log_info(logger, f"[INFO] Successfully retrieved traffic status for {len(ip_traffic_status)} IPs ({active_count} active)")
            return json.dumps(ip_traffic_status)
            
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to get traffic status for IPs: {e}")
            response.status = 500
            return {"error": str(e)}    
        
    @app.route('/api/trafficstats/<ip_address>', method=['GET'])
    def get_traffic_stats(ip_address):
        """
        API endpoint to get all traffic statistics for a specific IP address.

        Args:
            ip_address: The IP address to filter traffic statistics by.

        Returns:
            JSON object containing the traffic statistics for the specified IP address.
        """
        logger = logging.getLogger(__name__)
        try:
            
            # Call the function to get traffic stats for the IP address
            traffic_stats = get_traffic_stats_for_ip(ip_address)

            if traffic_stats:
                response.content_type = 'application/json'
                log_info(logger, f"[INFO] Successfully retrieved traffic stats for IP address {ip_address}")
                return json.dumps(traffic_stats, indent=2)
            else:
                response.content_type = 'application/json'
                log_warn(logger, f"[WARN] No traffic stats found for IP address {ip_address}")
                return json.dumps([])  # Return an empty list instead of a 404 error

        except Exception as e:
            log_error(logger, f"[ERROR] Failed to get traffic stats for IP address {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}