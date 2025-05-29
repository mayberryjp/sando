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



def setup_customtags_routes(app):
    """
    Set up routes for custom tags.

    Args:
        app: The Bottle application object
    """

    @app.route('/api/customtags', method='POST')
    def insert_tag():
        """
        Insert a new custom tag into the database.
        
        Expected JSON body:
        {
            "tag_id": "string",  # Optional - will be auto-generated if not provided
            "src_ip": "string",   # Source IP pattern (e.g. "192.168.1.*")
            "dst_ip": "string",   # Destination IP pattern
            "dst_port": "string", # Destination port pattern (e.g. "80" or "*")
            "protocol": "string", # Protocol pattern (e.g. "tcp" or "*")
            "tag_name": "string", # Optional - human-readable name
            "enabled": 1          # Optional - defaults to 1 (enabled)
        }
        
        Returns:
            JSON response with success status and tag ID
        """
        logger = logging.getLogger(__name__)
        
        # Set response type to JSON
        response.content_type = 'application/json'
        
        try:
            # Parse JSON request body
            data = request.json
            if not data:
                response.status = 400
                return {"success": False, "error": "No JSON data provided"}
            
            # Validate required fields
            required_fields = ["src_ip", "dst_ip", "dst_port", "protocol"]
            for field in required_fields:
                if field not in data:
                    response.status = 400
                    return {"success": False, "error": f"Missing required field: {field}"}
            
            # Generate a tag_id if not provided
            if "tag_id" not in data or not data["tag_id"]:
                import uuid
                data["tag_id"] = str(uuid.uuid4())
            
            # Get optional fields with defaults
            tag_name = data.get("tag_name", "")
            enabled = data.get("enabled", 1)
            
            # Call the database function to insert the tag
            from database.customtags import insert_custom_tag
            success, tag_id = insert_custom_tag(
                data["tag_id"], 
                data["src_ip"], 
                data["dst_ip"], 
                data["dst_port"], 
                data["protocol"],
                tag_name,
                enabled
            )
            
            if success:
                response.status = 201  # Created
                return {
                    "success": True, 
                    "tag_id": tag_id,
                    "message": "Custom tag created successfully"
                }
            else:
                response.status = 500
                return {"success": False, "error": "Failed to insert custom tag"}
                
        except ValueError as e:
            response.status = 400
            return {"success": False, "error": f"Invalid JSON data: {str(e)}"}
        except Exception as e:
            logger.error(f"Error inserting custom tag: {str(e)}")
            response.status = 500
            return {"success": False, "error": f"Server error: {str(e)}"}

    