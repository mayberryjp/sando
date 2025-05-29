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


# Define CORS headers
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
}

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
    app.run(host=API_LISTEN_ADDRESS, port=API_LISTEN_PORT, debug=False)