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

def setup_actions_routes(app):

    @app.route('/api/actions/all/acknowledge', method=['PUT'])
    def update_action_acknowledged_api():
        """
        API endpoint to update the acknowledged field for a specific action.

        Args:
            action_id: The ID of the action to update.

        Returns:
            JSON object indicating success or failure.
        """
        logger = logging.getLogger(__name__)
        try:
            
            if update_action_acknowledged_all():
                return {"message": f"Action with ID all acknowledged successfully"}
            else:
                response.status = 500
                return {"error": f"Failed to acknowledge actions"}
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to acknowledge actions: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route('/api/actions/<action_id>/acknowledge', method=['PUT'])
    def update_action_acknowledged_api(action_id):
        """
        API endpoint to update the acknowledged field for a specific action.

        Args:
            action_id: The ID of the action to update.

        Returns:
            JSON object indicating success or failure.
        """
        logger = logging.getLogger(__name__)
        try:
            
            if update_action_acknowledged(action_id):
                return {"message": f"Action with ID {action_id} acknowledged successfully"}
            else:
                response.status = 500
                return {"error": f"Failed to acknowledge action with ID {action_id}"}
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to acknowledge action with ID {action_id}: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route('/api/actions', method=['POST'])
    def insert_action_api():
        """
        API endpoint to insert a new action into the database.

        Returns:
            JSON object indicating success or failure.
        """
        logger = logging.getLogger(__name__)
        try:
            action_data = request.json
            if insert_action(action_data):
                return {"message": "Action inserted successfully"}
            else:
                response.status = 500
                return {"error": "Failed to insert action"}
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to insert action: {e}")
            response.status = 500
            return {"error": str(e)}


    @app.route('/api/actions', method=['GET'])
    def get_actions():
        """
        API endpoint to retrieve all actions from the database.

        Returns:
            JSON object containing all actions.
        """
        logger = logging.getLogger(__name__)
        try:
            actions = get_all_actions()
            response.content_type = 'application/json'
            return json.dumps(actions, indent=2)
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to retrieve actions: {e}")
            response.status = 500
            return {"error": str(e)}