import json
import logging

from bottle import Bottle, request, response

from src.database.configuration import get_config_settings, update_config_setting
from src.utils.locallogging import log_error, log_info

app = Bottle()


def setup_configurations_routes(app):

    @app.route("/api/configurations", method=["GET", "POST"])
    def configurations():
        """
        API endpoint to get all configurations or add a new configuration.

        Returns:
            JSON array containing all configurations for GET requests or
            a success/error message for POST requests.
        """
        logger = logging.getLogger(__name__)

        if request.method == "GET":
            try:
                # Use the existing function to get all configurations
                config_dict = get_config_settings()

                if not config_dict:
                    log_error(
                        logger, "[ERROR] Failed to retrieve configuration settings"
                    )
                    response.status = 500
                    return {"error": "Failed to retrieve configuration settings"}

                # Transform dictionary to list of key-value pairs to maintain API compatibility
                config_list = [
                    {"key": key, "value": value} for key, value in config_dict.items()
                ]

                response.content_type = "application/json"
                log_info(logger, "[INFO] Fetched all configurations successfully")
                return json.dumps(config_list)

            except Exception as e:
                log_error(logger, f"[ERROR] Failed to fetch configurations: {e}")
                response.status = 500
                return {"error": str(e)}

        elif request.method == "POST":
            # For POST requests, we still need to implement direct database access
            # since there's no matching function in database.py
            data = request.json
            key = data.get("key")
            value = data.get("value")

            if not key or value is None:
                response.status = 400
                return {"error": "Key and value are required"}

            try:
                update_config_setting(key, value)

                response.content_type = "application/json"
                log_info(logger, f"[INFO] Added new configuration: {key}")
                return {"message": "Configuration added successfully"}

            except Exception as e:
                log_error(logger, f"[ERROR] Error adding configuration: {e}")
                response.status = 500
                return {"error": str(e)}
