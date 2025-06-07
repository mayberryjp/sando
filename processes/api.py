import sys
import os
from pathlib import Path
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
from bottle import Bottle, request, response, hook, route
import logging
# Import DNS lookup function
from init import *
from routers.actions import *
from routers.agent import *
from routers.alerts import *
from routers.configurations import *
from routers.ignorelist import *
from routers.localhosts import *
from routers.services import *
from routers.trafficstats import *
from routers.integrations import *
from routers.customtags import *
from routers.threatscore import *
from routers.devices import *
from routers.explore import *
from routers.localhoststags import *

# Initialize the Bottle app
app = Bottle()

setup_actions_routes(app)
setup_agent_routes(app)
setup_alerts_routes(app)
setup_configurations_routes(app)
setup_ignorelist_routes(app)
setup_integrations_routes(app)
setup_localhosts_routes(app)
setup_services_routes(app)
setup_trafficstats_routes(app)
setup_configurations_routes(app)
setup_devices_routes(app)
setup_threatscore_routes(app)
setup_explore_routes(app)
setup_localhoststags_routes(app)

# Define CORS headers
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
}

from database.common import test_database_online



@app.get('/api/online/<db_name>')
def api_online_db(db_name):
    """
    Health check endpoint to test if a specific database is online.
    Returns JSON: {"online": true/false}
    """
    db_map = {
        'consolidated': CONST_CONSOLIDATED_DB,
        'explore': CONST_EXPLORE_DB
    }
    
    db_path = db_map.get(db_name.lower())
    
    if not db_path:
        response.status = 404
        return {"online": False, "error": "Database not found"}
    
    try:
        result = test_database_online(db_path)
        response.content_type = 'application/json'
        return {"online": bool(result)}
    except Exception as e:
        response.status = 500
        return {"online": False, "error": str(e)}
    

def api_online():
    """
    Health check endpoint to test if the main database is online.
    Returns JSON: {"online": true/false}
    """
    try:
        result = test_database_online(CONST_CONSOLIDATED_DB)
        response.content_type = 'application/json'
        return {"online": bool(result)}
    except Exception as e:
        response.status = 500
        return {"online": False, "error": str(e)}

# Add CORS headers to all responses
@app.hook('after_request')
def enable_cors():
    """Add CORS headers to every response"""
    for key, value in CORS_HEADERS.items():
        response.headers[key] = value

# Handle OPTIONS preflight requests
@app.route('/<path:path>', method='OPTIONS')
@app.route('/', method='OPTIONS')
def options_handler(path=None):
    """Handle OPTIONS requests for CORS preflight"""
    # Set CORS headers explicitly for OPTIONS
    for key, value in CORS_HEADERS.items():
        response.headers[key] = value
    return {}

if IS_CONTAINER:
    API_LISTEN_ADDRESS = os.getenv("API_LISTEN_ADDRESS", CONST_API_LISTEN_ADDRESS)
    API_LISTEN_PORT = os.getenv("API_LISTEN_PORT", CONST_API_LISTEN_PORT)

# Helper function to set JSON response headers

# Run the Bottle app
if __name__ == '__main__':
    logger = logging.getLogger(__name__) 
    log_info(logger, "Starting API server...")
    from waitress import serve
    serve(app, host=API_LISTEN_ADDRESS, port=int(API_LISTEN_PORT), threads=20)