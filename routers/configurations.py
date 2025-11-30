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

def setup_configurations_routes(app):
        
    @app.route('/api/configurations', method=['GET', 'POST'])
    def configurations():
        """
        API endpoint to get all configurations or add a new configuration.
        
        Returns:
            JSON array containing all configurations for GET requests or
            a success/error message for POST requests.
        """
        logger = logging.getLogger(__name__)
        
        if request.method == 'GET':
            try:
                # Use the existing function to get all configurations
                config_dict = get_config_settings()
                
                if not config_dict:
                    log_error(logger, "[ERROR] Failed to retrieve configuration settings")
                    response.status = 500
                    return {"error": "Failed to retrieve configuration settings"}
                
                # Transform dictionary to list of key-value pairs to maintain API compatibility
                config_list = [{"key": key, "value": value} for key, value in config_dict.items()]
                
                response.content_type = 'application/json'
                log_info(logger, "[INFO] Fetched all configurations successfully")
                return json.dumps(config_list)
                
            except Exception as e:
                log_error(logger, f"[ERROR] Failed to fetch configurations: {e}")
                response.status = 500
                return {"error": str(e)}
        
        elif request.method == 'POST':
            # For POST requests, we still need to implement direct database access
            # since there's no matching function in database.py
            data = request.json
            key = data.get('key')
            value = data.get('value')
            
            if not key or value is None:
                response.status = 400
                return {"error": "Key and value are required"}
            
            try:
                update_config_setting(key, value)
                
                response.content_type = 'application/json'
                log_info(logger, f"[INFO] Added new configuration: {key}")
                return {"message": "Configuration added successfully"}
                
            except Exception as e:
                log_error(logger, f"[ERROR] Error adding configuration: {e}")
                response.status = 500
                return {"error": str(e)}
