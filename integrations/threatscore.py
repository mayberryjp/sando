import sys
import os
import logging
import sqlite3
from pathlib import Path

# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *
from database.alerts import summarize_alerts_by_ip
from database.localhosts import update_localhost_threat_score
from database.trafficstats import get_all_ips_traffic_status

def calculate_update_threat_scores():
    """
    Calculate threat scores for all hosts in the localhosts database based on their alert counts.
    Updates the threat_score field in the database for each localhost.
    
    Threat score is on a scale of 0-100, where:
    - 0: No alerts (safe)
    - 1-25: Low threat (few alerts)
    - 26-50: Medium threat
    - 51-75: High threat
    - 76-100: Critical threat (many alerts)
    
    Returns:
        dict: A dictionary with IP addresses as keys and calculated threat scores as values
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting threat score calculation for all hosts")
    
    # Get all localhosts
    localhosts = get_localhosts()
    if not localhosts:
        log_warn(logger, "[WARN] No localhosts found in database for threat scoring")
        return {}
    
    # Get alert summaries for each IP using existing summarize_alerts_by_ip function
    alerts_summary = summarize_alerts_by_ip_last_seen()
    
    # Process the alert summary to get total counts per IP
    alert_counts = {}
    for ip_address, data in alerts_summary.items():
        if "alert_intervals" in data:
            # Sum up all hourly alert counts
            total_alerts = sum(data["alert_intervals"])
            alert_counts[ip_address] = total_alerts
    
    # Find maximum alerts to scale properly
    max_alerts = 1  # Prevent division by zero
    if alert_counts:
        max_alerts = max(alert_counts.values()) or 1
        
    # Set scaling threshold - if any host has more than this number of alerts,
    # we'll consider that as reaching the maximum threat score
    scaling_threshold = 50
    actual_max = max(max_alerts, scaling_threshold)
    
    # Calculate and update threat scores
    results = {}
    
    # Get traffic status for all IPs
    traffic_status = get_all_ips_traffic_status()  # Returns {ip: True/False}

    for ip_address in localhosts:
        try:
            # Set threat_score to -1 if no traffic
            if not traffic_status.get(ip_address, False):
                threat_score = -1
                log_info(logger, f"[INFO] No traffic for {ip_address}, setting threat score to -1")
            else:
                # Get alert count for this IP
                alert_count = alert_counts.get(ip_address, 0)
                
                # Calculate threat score (0-100 scale)
                # We use a non-linear scaling to emphasize differences at lower counts
                if alert_count == 0:
                    threat_score = 0
                else:
                    # Apply non-linear scaling that gives more weight to the first few alerts
                    if alert_count < 5:
                        # Low counts: 1 alert → 10, 2 alerts → 20, etc.
                        threat_score = min(10 * alert_count, 100)
                    elif alert_count < 20:
                        # Medium counts: diminishing returns but still significant
                        threat_score = min(40 + (alert_count - 5) * 2, 100)
                    else:
                        # High counts: slower increase
                        threat_score = min(70 + (alert_count - 20) * 0.5, 100)
                
                # Round to integer
                threat_score = round(threat_score)
                log_info(logger, f"[DEBUG] Calculated threat score for {ip_address}: {threat_score} (based on {alert_count} alerts)")
            
            # Update the localhost's threat score in the database
            success = update_localhost_threat_score(ip_address, threat_score)
            
            if success:
                log_info(logger, f"[INFO] Updated threat score for {ip_address}: {threat_score} (based on {alert_count} alerts)")
            else:
                log_error(logger, f"[ERROR] Failed to update threat score for {ip_address}")
                
            results[ip_address] = threat_score
            
        except Exception as e:
            log_error(logger, f"[ERROR] Error calculating threat score: {e}")
    
    log_info(logger, f"[INFO] Completed threat score updates for {len(results)} hosts")
    return results
