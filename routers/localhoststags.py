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

def setup_localhoststags_routes(app):

    @app.put('/api/localhosts/tag/<ip_address>')
    def api_add_tag(ip_address):
        """
        Add a tag to the specified localhost.
        Expects JSON body: {"tag": "tagname"}
        """
        try:
            data = request.json
            tag = data.get("tag") if data else None
            if not tag:
                response.status = 400
                return {"success": False, "error": "Missing 'tag' in request body"}
            add_tag_to_localhost(ip_address, tag)
            return {"success": True, "message": f"Tag '{tag}' added to {ip_address}"}
        except Exception as e:
            response.status = 500
            return {"success": False, "error": str(e)}

    @app.delete('/api/localhosts/tag/<ip_address>')
    def api_delete_tag(ip_address):
        """
        Remove a tag from the specified localhost.
        Expects JSON body: {"tag": "tagname"}
        """
        try:
            data = request.json
            tag = data.get("tag") if data else None
            if not tag:
                response.status = 400
                return {"success": False, "error": "Missing 'tag' in request body"}
            delete_tag_from_localhost(ip_address, tag)
            return {"success": True, "message": f"Tag '{tag}' removed from {ip_address}"}
        except Exception as e:
            response.status = 500
            return {"success": False, "error": str(e)}