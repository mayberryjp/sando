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
import json
from init import *
from src.devicecategories import CONST_DEVICE_CATEGORIES
from database.explore import get_latest_master_flows, search_master_flows_by_concat

app = Bottle()

def setup_explore_routes(app):
    """
    Set up routes for exploration.

    Args:
        app: The Bottle application object
    """

    @app.get('/api/explore')
    def api_explore():
        """
        Returns the latest master flows with pagination.
        Query params:
            limit (int): Number of rows per page (default 1000)
            page (int): Page number (default 0)
        """
        try:
            limit = int(request.query.get('limit', 100))
            page = int(request.query.get('page', 0))
            data = get_latest_master_flows(limit=limit, page=page)
            response.content_type = 'application/json'
            return json.dumps({"success": True, "data": data})
        except Exception as e:
            response.status = 500
            return json.dumps({"success": False, "error": str(e)})

    @app.get('/api/explore/search')
    def api_explore_search():
        """
        Search master flows by concat column with pagination.
        Query params:
            q (str): Search string (required)
            page (int): Page number (default 0)
            page_size (int): Number of rows per page (default 1000)
        """
        try:
            search_string = request.query.get('q', '')
            if "_" in search_string:
                search_string = search_string.replace("_", r"\_")
            if not search_string:
                response.status = 400
                return json.dumps({"success": False, "error": "Missing required parameter: q"})
            page = int(request.query.get('page', 0))
            page_size = int(request.query.get('page_size', 100))
            data = search_master_flows_by_concat(search_string, page=page, page_size=page_size)
            response.content_type = 'application/json'
            return json.dumps({"success": True, "data": data})
        except Exception as e:
            response.status = 500
            return json.dumps({"success": False, "error": str(e)})

