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
# Import the threat score calculation function
from integrations.threatscore import calculate_update_threat_scores
app = Bottle()

def setup_threatscore_routes(app):
    
    @app.route('/api/threatscore', method=['POST'])
    def recalculate_threat_scores():
        """
        API endpoint to force recalculation of all threat scores.
        
        Returns:
            JSON object containing the results of the calculation with
            IP addresses as keys and their newly calculated threat scores as values.
        """
        logger = logging.getLogger(__name__)
        
        try:
            log_info(logger, "[INFO] Received request to recalculate all threat scores")
            
            # Call the function to calculate and update threat scores
            results = calculate_update_threat_scores()
            
            # Return the results as JSON
            response.content_type = 'application/json'
            
            # Create a more informative response
            response_data = {
                "success": True,
                "message": f"Successfully recalculated threat scores for {len(results)} hosts",
                "host_count": len(results),
                "scores": results
            }
            
            log_info(logger, f"[INFO] Completed threat score recalculation for {len(results)} hosts")
            return response_data
            
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to recalculate threat scores: {e}")
            response.status = 500
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to recalculate threat scores"
            }

