import json
import logging

from bottle import Bottle, response

from src.utils.devicecategories import CONST_DEVICE_CATEGORIES
from src.utils.locallogging import log_error, log_info

app = Bottle()


def setup_devices_routes(app):
    """
    Set up routes for device categories.

    Args:
        app: The Bottle application object
    """

    @app.route("/api/devices", method=["GET"])
    def get_device_categories():
        """
        API endpoint to get all device categories.

        Returns:
            JSON array containing only the category names without icons.
        """
        logger = logging.getLogger(__name__)

        try:
            # Extract only the category names from the device categories
            category_names = [item["category"] for item in CONST_DEVICE_CATEGORIES]

            response.content_type = "application/json"
            log_info(
                logger,
                f"[INFO] Fetched {len(category_names)} device category names successfully",
            )
            return json.dumps(category_names, indent=2)

        except Exception as e:
            log_error(logger, f"[ERROR] Failed to fetch device categories: {e}")
            response.status = 500
            return {"error": str(e)}
