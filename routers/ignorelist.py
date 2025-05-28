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

def setup_ignorelist_routes(app):

    # API for CONST_CONSOLIDATED_DB
    @app.route('/api/ignorelist', method=['GET', 'POST'])
    def ignorelist():
        """
        API endpoint to get all ignorelist entries or add a new entry.
        
        Returns:
            JSON array containing all ignorelist entries for GET requests or
            a success/error message for POST requests.
        """
        logger = logging.getLogger(__name__)
        
        if request.method == 'GET':
            try:
                # Use the database function to get all ignorelist entries
                ignorelist_entries = get_ignorelist()
                
                if ignorelist_entries is None:
                    log_error(logger, "[ERROR] Failed to retrieve ignorelist entries")
                    response.status = 500
                    return {"error": "Failed to retrieve ignorelist entries"}
                
                # Format the response to match the expected structure
                formatted_entries = []
                for entry in ignorelist_entries:
                    formatted_entry = {
                        "ignorelist_id": entry[0],
                        "src_ip": entry[1],
                        "dst_ip": entry[2],
                        "dst_port": entry[3],
                        "protocol": entry[4],
                        "added": datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Use current time as fallback
                    }
                    formatted_entries.append(formatted_entry)
                
                response.content_type = 'application/json'
                log_info(logger, f"[INFO] Fetched {len(formatted_entries)} ignorelist entries successfully")
                return json.dumps(formatted_entries)
                
            except Exception as e:
                log_error(logger, f"[ERROR] Failed to fetch ignorelist entries: {e}")
                response.status = 500
                return {"error": str(e)}
        
        elif request.method == 'POST':
            # Add a new ignorelist entry
            data = request.json
            
            ignorelist_id = data.get("ignorelist_id")
            src_ip = data.get('src_ip')
            dst_ip = data.get('dst_ip')
            dst_port = data.get('dst_port')
            protocol = data.get('protocol')
            
            if not ignorelist_id or not src_ip or not dst_ip or not dst_port or not protocol:
                response.status = 400
                return {"error": "Required fields missing (ignorelist_id, src_ip, dst_ip, dst_port, dst_protocol)"}
            
            try:

                insert_ignorelist_entry(ignorelist_id, src_ip, dst_ip, dst_port, protocol)
                
                response.content_type = 'application/json'
                log_info(logger, f"[INFO] Added new ignorelist entry: {ignorelist_id} {src_ip} -> {dst_ip}:{dst_port}/{protocol}")
                return {"message": "IgnoreList entry added successfully"}
                
            except Exception as e:
                log_error(logger, f"[ERROR] Error adding ignorelist entry: {e}")
                response.status = 500
                return {"error": str(e)}

    @app.route('/api/ignorelist/<id>', method=['DELETE'])
    def modify_ignorelist(id):
        logger = logging.getLogger(__name__)

        if request.method == 'DELETE':
            # Delete a ignorelist entry
            try:
                delete_ignorelist_entry(id)
                response.content_type = 'application/json'
                log_info(logger, f"Deleted ignorelist entry: {id}")
                return {"message": "IgnoreList entry deleted successfully"}
            except Exception as e:
                log_error(logger, f"Error deleting ignorelist entry: {e}")
                response.status = 500
                return {"error": str(e)}
            

    @app.route('/api/ignorelist/ip/<ip_address>', method=['GET'])
    def get_ignorelist_by_ip(ip_address):
        """
        API endpoint to get all ignorelist entries for a specific IP address.
        
        Args:
            ip_address (str): The IP address to filter ignorelist entries by
            
        Returns:
            JSON array containing all ignorelist entries for the specified IP address
        """
        logger = logging.getLogger(__name__)
        
        try:
            # Use the function to get ignorelist entries for the IP
            ignorelist_entries = get_ignorelist_for_ip(ip_address)
            
            if ignorelist_entries is None:
                log_error(logger, f"[ERROR] Failed to retrieve ignorelist entries for IP {ip_address}")
                response.status = 500
                return {"error": "Failed to retrieve ignorelist entries"}
            
            # Format the response to match the expected structure
            # formatted_entries = []
            # for entry in ignorelist_entries:
            #     formatted_entry = {
            #         "ignorelist_id": entry[0],
            #         "src_ip": entry[1],
            #         "dst_ip": entry[2],
            #         "dst_port": entry[3],
            #         "protocol": entry[4]
            #     }
            #     formatted_entries.append(formatted_entry)
            
            response.content_type = 'application/json'
          #  log_info(logger, f"[INFO] Fetched {len(formatted_entries)} ignorelist entries for IP {ip_address}")
            return json.dumps(ignorelist_entries)
            
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to fetch ignorelist entries for IP {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}