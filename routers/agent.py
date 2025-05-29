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
from integrations.dns import dns_lookup
# Import geolocation function
from integrations.geolocation import lookup_ip_country


def setup_agent_routes(app):


    @app.route('/api/investigate/<ip_address>', method=['GET'])
    def investigate_ip(ip_address):
        """
        API endpoint to investigate an IP address by performing reverse DNS lookup
        and geolocation lookup.

        Args:
            ip_address: The IP address to investigate.

        Returns:
            JSON object containing the IP address, country, and DNS lookup results.
        """
        logger = logging.getLogger(__name__)
        try:
            result = {
                "ip_address": ip_address,
                "dns": None,
                "country": None,
                "isp": None
            }
            
            # Get configuration settings
            config_dict = get_config_settings()

            DNS_SERVERS = config_dict['ApprovedLocalDnsServersList'].split(',')

            if DNS_SERVERS and config_dict.get('DiscoveryReverseDns', 0) > 0:
                dns_results = dns_lookup([ip_address], DNS_SERVERS, config_dict)
                log_info(logger, f"[INFO] DNS Results: {dns_results}")
                
                # Handle the returned format properly
                if isinstance(dns_results, list):
                    # Find the result for our IP
                    for entry in dns_results:
                        if entry.get('ip') == ip_address:
                            result["dns"] = entry.get('dns_hostname')
                            break
                elif isinstance(dns_results, dict) and ip_address in dns_results:
                    # Handle the old format for backward compatibility
                    result["dns"] = dns_results[ip_address]
            else:
                log_info(logger, "[INFO] DNS lookup skipped - no DNS servers configured or discovery disabled")

            isp_result = get_asn_for_ip(ip_address)

            if isp_result:
                result["isp"] = isp_result["isp_name"]
            else:
                log_info(logger, f"[INFO] No ISP result found for IP: {ip_address}")

            # Perform geolocation lookup
            geo_result = lookup_ip_country(ip_address)
            if geo_result:
                result["country"] = geo_result
            else:
                log_info(logger, f"[INFO] No geolocation result found for IP: {ip_address}")

            response.content_type = 'application/json'
            log_info(logger, f"[INFO] Successfully investigated IP address: {ip_address}")
            return json.dumps(result, indent=2)
            
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to investigate IP address {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}
        
    @app.route('/api/classify/<ip_address>', method=['GET'])
    def classify_client_api(ip_address):
        """
        API endpoint to classify a client device by retrieving its data definition
        and sending it to the master classification API.

        Args:
            ip_address: The IP address of the client to classify.

        Returns:
            JSON object containing the classification results.
        """
        logger = logging.getLogger(__name__)
        try:
            # Import the required functions
            from src.client import export_client_definition, classify_client
            from database.common import get_machine_unique_identifier_from_db
            
            # Get the machine identifier
            machine_identifier = get_machine_unique_identifier_from_db()
            if not machine_identifier:
                log_error(logger, f"[ERROR] Failed to get machine identifier for classification")
                response.status = 500
                return {"error": "Could not retrieve machine identifier"}
                
            # Get client definition
            client_data = export_client_definition(ip_address)
            if not client_data:
                log_warn(logger, f"[WARN] No client data found for {ip_address}")
                response.status = 404
                return {"error": f"No client data found for {ip_address}"}
            
            # Send to classification API
            classification_result = classify_client(machine_identifier, client_data)
            if not classification_result:
                log_error(logger, f"[ERROR] Failed to classify client {ip_address}")
                response.status = 500
                return {"error": "Classification request failed"}
            
            # Return the classification result
            response.content_type = 'application/json'
            log_info(logger, f"[INFO] Successfully classified client {ip_address}")
            return json.dumps(classification_result, indent=2)
            
        except Exception as e:
            log_error(logger, f"[ERROR] Failed to classify client {ip_address}: {e}")
            response.status = 500
            return {"error": str(e)}
        