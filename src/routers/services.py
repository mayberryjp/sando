import json
import logging
import sqlite3

from bottle import Bottle, response

from src.utils.locallogging import log_error, log_info

app = Bottle()


def setup_services_routes(app):
    @app.route("/api/services/<port>", method=["GET"])
    def get_services_by_port_api(port):
        """
        API endpoint to get service information for a specific port.

        Args:
            port (str): The port number to retrieve service information for.

        Returns:
            JSON object containing service information for the specified port.
        """
        logger = logging.getLogger(__name__)

        try:
            # Convert port to integer
            port_number = int(port)

            # Import the function from src.database.py
            from src.database.services import get_services_by_port

            # Get service information for the port
            services = get_services_by_port(port_number)

            if not services:
                log_info(logger, f"[INFO] No services found for port {port_number}")
                return json.dumps({})

            response.content_type = "application/json"
            log_info(
                logger, f"[INFO] Retrieved service information for port {port_number}"
            )
            return json.dumps(services, indent=2)

        except ValueError:
            log_error(logger, f"[ERROR] Invalid port number: {port}")
            response.status = 400
            return {"error": "Invalid port number"}
        except sqlite3.Error as e:
            log_error(
                logger, f"[ERROR] Database error fetching services for port {port}: {e}"
            )
            response.status = 500
            return {"error": str(e)}
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to get services for port {port}: {e}")
            response.status = 500
            return {"error": str(e)}
