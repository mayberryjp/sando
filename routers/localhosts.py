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

def setup_localhosts_routes(app):
    # API for CONST_CONSOLIDATED_DB
    @app.route('/api/localhosts', method=['GET'])
    def localhosts():
        """
        API endpoint to get all local hosts.

        Returns:
            JSON array containing all local hosts.
        """
        logger = logging.getLogger(__name__)
        
        try:
            # Use the existing function to get all localhosts
            localhosts_data = get_localhosts_all()
            
            if not localhosts_data:
                log_warn(logger, "[WARN] No local hosts found in the database")
                # Return empty array rather than error
                response.content_type = 'application/json'
                return json.dumps([])
            
            response.content_type = 'application/json'
            log_info(logger, f"[INFO] Fetched {len(localhosts_data)} local hosts successfully")
            return json.dumps(localhosts_data, indent=2)
            
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to fetch local hosts: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route('/api/localhosts/<ip_address>', method=['PUT'])
    def modify_localhost(ip_address):
        """
        API endpoint to update properties of an existing localhost device.
        Now accepts 'mac_address' in the request body.
        """
        logger = logging.getLogger(__name__)

        if request.method == 'PUT':
            data = request.json
            local_description = data.get('local_description')
            icon = data.get('icon')
            management_link = data.get('management_link')
            mac_address = data.get('mac_address')  # <-- Accept mac_address
            ip_address = data.get('ip_address')  # Allow updating IP address if provided

            try:
                # Update the localhost classification in the database
                # You need to update classify_localhost to accept mac_address if you want to store it
                classify_localhost(ip_address, local_description, icon, management_link, mac_address)

                response.content_type = 'application/json'
                log_info(logger, f"Updated local host: {ip_address} (MAC: {mac_address})")
                return {"message": "Local host updated successfully"}
            except Exception as e:
                log_error(logger, f"Error updating local host: {e}")
                response.status = 500
                return {"error": str(e)}

    @app.route('/api/localhosts/<ip_address>', method=['DELETE'])
    def delete_localhost(ip_address):
        """
        API endpoint to delete a local host by its IP address.

        Args:
            ip_address: The IP address of the local host to delete.

        Returns:
            JSON object indicating success or failure.
        """
        logger = logging.getLogger(__name__)

        try:
            delete_localhost_database(ip_address)
            # Delete the local host with the specified IP address
            response.content_type = 'application/json'
            log_info(logger, f"[INFO] Deleted local host with IP address: {ip_address}")
            return {"message": f"Local host with IP address {ip_address} deleted successfully"}
        except Exception as e:
            log_error(logger, f"[ERROR] Error deleting local host with IP address {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}
        except Exception as e:
            log_error(logger, f"[ERROR] Unexpected error deleting local host with IP address {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}
        

    @app.route('/api/localhosts/<ip_address>', method=['GET'])
    def get_localhost(ip_address):
        """
        API endpoint to get information for a single local host by IP address.

        Args:
            ip_address: The IP address of the local host to retrieve.

        Returns:
            JSON object containing the local host's details or an error message.
        """
        logger = logging.getLogger(__name__)
        
        try:
            # Call the database function to get the localhost details
            host_record = get_localhost_by_ip(ip_address)
            
            if host_record:
                # Ensure it's a properly formatted dictionary with all fields
                localhost_dict = {
                    "ip_address": host_record[0],
                    "mac_address": host_record[3],
                    "mac_vendor": host_record[4],
                    "dhcp_hostname": host_record[5],
                    "dns_hostname": host_record[6],
                    "os_fingerprint": host_record[7],
                    "lease_hostname": host_record[8],
                    "lease_hwaddr": host_record[9],
                    "lease_clientid": host_record[10],
                    "acknowledged": host_record[11],
                    "tags": host_record[14] if host_record[14] else [],
                    "threat_score": host_record[15],
                    "alerts_enabled": host_record[16],
                    "management_link": host_record[17],
                    "original_flow": host_record[2],
                    "icon": host_record[13],
                    "local_description": host_record[12],
                    "first_seen": host_record[1],
                    "last_dhcp_discover": host_record[18]
                }
                
                response.content_type = 'application/json'
                log_info(logger, f"[INFO] Fetched local host details for IP address: {ip_address}")
                return json.dumps(localhost_dict, indent=2)
            else:
                log_warn(logger, f"[WARN] No local host found for IP address: {ip_address}")
                response.status = 404
                return {"error": f"No local host found for IP address: {ip_address}"}
                
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to fetch local host for IP address {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}
        
    @app.route('/api/localhosts/<ip_address>/alerts-enabled', method=['PUT'])
    def toggle_localhost_alerts(ip_address):
        """
        API endpoint to toggle the alerts_enabled flag for a specific local host.

        Args:
            ip_address: The IP address of the local host to update.

        Request body:
            {
                "alerts_enabled": true|false  (Boolean value to enable/disable alerts)
            }

        Returns:
            JSON object indicating success or failure.
        """
        logger = logging.getLogger(__name__)
        
        try:
            # Parse request body
            data = request.json
            if not data or 'alerts_enabled' not in data:
                response.status = 400
                return {"success": False, "error": "Missing required field: alerts_enabled"}
            
            # Get the alerts_enabled value
            alerts_enabled = bool(data['alerts_enabled'])
            
            # Call the database function to update the alerts_enabled flag
            from database.localhosts import update_localhost_alerts_enabled
            success = update_localhost_alerts_enabled(ip_address, alerts_enabled)
            
            if success:
                response.content_type = 'application/json'
                log_info(logger, f"[INFO] Updated alerts_enabled to {alerts_enabled} for IP address: {ip_address}")
                return {"success": True, "ip_address": ip_address, "alerts_enabled": alerts_enabled}
            else:
                log_warn(logger, f"[WARN] Failed to update alerts_enabled for IP address: {ip_address}")
                response.status = 404
                return {"success": False, "error": f"No local host found with IP address: {ip_address}"}
                
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to update alerts_enabled for IP address {ip_address}: {e}")
            response.status = 500
            return {"success": False, "error": str(e)}