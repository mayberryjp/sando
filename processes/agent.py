import sys
from pathlib import Path
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from init import *

import os
import json
import logging
import requests
import re
from datetime import datetime
from difflib import get_close_matches
from bottle import Bottle, request, response, run

# Set up logging
logger = logging.getLogger(__name__)

# Configuration 
class Config:
    API_BASE_URL = "http://127.0.0.1:8044/api"

app = Bottle()

# Define available API endpoints and their descriptions
API_ENDPOINTS = [
    # Alert management endpoints
    # Client/Host information endpoints
    {
        "name": "get_client_info",
        "endpoint": "/client/{ip_address}",
        "method": "GET",
        "description": "Get detailed information about a client with the given IP address",
        "keywords": ["client", "info", "details", "host", "ip"],
        "params": ["ip_address"]
    },
    {
        "name": "get_localhost_by_ip",
        "endpoint": "/localhosts/{ip_address}",
        "method": "GET",
        "description": "Get details for a specific local host",
        "keywords": ["local", "host", "device", "details", "ip"],
        "params": ["ip_address"]
    },
    # Classification endpoint
    {
        "name": "classify_device",
        "endpoint": "/classify",
        "method": "POST",
        "description": "Classify a device based on DNS query or IP address",
        "keywords": ["classify", "identify", "device", "ip", "dns", "domain"],
        "params": ["identifier"]
    },
    
    # Configuration endpoints
    {
        "name": "get_configurations",
        "endpoint": "/configurations",
        "method": "GET",
        "description": "Get all system configurations",
        "keywords": ["configurations", "settings", "options", "version", "site name"],
        "params": []
    },   
    # Status and statistics endpoints
    {
        "name": "get_statistics",
        "endpoint": "/quickstats",
        "method": "GET",
        "description": "Get quick statistics about the database (alert counts, host counts, etc.)",
        "keywords": ["stats", "statistics", "counts", "dashboard", "overview", "database"],
        "params": []
    },
    {
        "name": "get_integration_stats",
        "endpoint": "/homeassistant",
        "method": "GET",
        "description": "Get statistics for third party integrations",
        "keywords": ["third", "party", "integrations", "integration", "stats"],
        "params": []
    },

# Add this to the API_ENDPOINTS list
    {
        "name": "remote_ip",
        "endpoint": "/investigate/{ip_address}",
        "method": "GET",
        "description": "Investigate an IP address with DNS and geolocation lookups",
        "keywords": ["investigate", "lookup", "trace", "check", "ip", "country", "dns", "location", "geo", "remote"],
        "params": ["ip_address"]
    },
# Add this to the API_ENDPOINTS list in processes/agent.py
    {
        "name": "get_services_by_port",
        "endpoint": "/services/{port}",
        "method": "GET",
        "description": "Get information about network services that use a specific port number",
        "keywords": ["port", "service", "services", "protocol", "tcp", "udp", "lookup", "what", "runs", "running"],
        "params": ["port"]
    },
# Add this to the API_ENDPOINTS list in agent.py
    {
        "name": "classify_client",
        "endpoint": "/classify/{ip_address}",
        "method": "GET",
        "description": "Classify a client device using machine learning to identify its type and purpose",
        "keywords": ["classify", "identify", "client", "device", "type", "what", "is", "machine", "learning", "ml"],
        "params": ["ip_address"]
    }
]

class NLPProcessor:
    def __init__(self, config, api_endpoints):
        self.config = config
        self.api_endpoints = api_endpoints
        self.openai_client = None  # Always set to None to disable OpenAI
        
    def extract_intent_and_params(self, text):
        """Use NLP to determine the intent and extract parameters from text"""
        # Always use basic NLP without trying OpenAI
        return self.extract_with_basic_nlp(text)
    
    def extract_with_basic_nlp(self, text):
        """Use advanced NLP techniques to determine intent and extract parameters without OpenAI"""
        text = text.lower()
        
        # 1. First approach: Weighted keyword matching
        endpoint_scores = []
        for endpoint in self.api_endpoints:
            # Base score from exact keyword matches
            keyword_score = sum(3 for keyword in endpoint["keywords"] if keyword.lower() in text)
            
            # Bonus for verb matching (get, delete, update)
            method_verb = endpoint["method"].lower()
            method_verbs = {
                "get": ["get", "show", "display", "list", "view", "find", "search", "what"],
                "delete": ["delete", "remove", "clear", "erase"],
                "put": ["update", "change", "modify", "edit", "set"],
                "post": ["add", "create", "insert", "new"]
            }
            
            if method_verb in method_verbs:
                verb_score = sum(2 for verb in method_verbs[method_verb] if verb in text)
                keyword_score += verb_score
            
            # Bonus for relevant entity presence
            if any(param in ["ip_address", "identifier"] for param in endpoint["params"]):
                if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):  # IP address
                    keyword_score += 3
                    
            if "domain" in endpoint["description"].lower() or "dns" in endpoint["description"].lower():
                if re.search(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', text):
                    keyword_score += 3
            
            # 2. Context matching using word proximity
            context_score = 0
            for i, keyword1 in enumerate(endpoint["keywords"]):
                if keyword1 in text:
                    # Find other keywords nearby (within 5 words)
                    keyword_pos = text.find(keyword1)
                    nearby_text = text[max(0, keyword_pos-30):min(len(text), keyword_pos+30)]
                    for keyword2 in endpoint["keywords"][i+1:]:
                        if keyword2 in nearby_text:
                            context_score += 1
            
            total_score = keyword_score + context_score
            endpoint_scores.append((endpoint, total_score))
        
        # Sort by score in descending order
        endpoint_scores.sort(key=lambda x: x[1], reverse=True)
        
        # If top two scores are close, use more heuristics to decide
        if len(endpoint_scores) > 1 and endpoint_scores[0][1] > 0:
            if endpoint_scores[0][1] - endpoint_scores[1][1] < 2:
                # Check parameter presence for tiebreaking
                top_endpoints = [endpoint_scores[0][0], endpoint_scores[1][0]]
                for endpoint in top_endpoints:
                    for param in endpoint["params"]:
                        param_patterns = {
                            "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                            "identifier": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
                            "id": r'\b(?:id|alert|entry)[\s:]?([a-zA-Z0-9_-]+)\b',
                            "category_name": r'\bcategory[\s:]?([a-zA-Z0-9_-]+)\b'
                        }
                        
                        if param in param_patterns and re.search(param_patterns[param], text):
                            if endpoint == endpoint_scores[1][0]:
                                # Swap positions if second endpoint's param is found
                                endpoint_scores[0], endpoint_scores[1] = endpoint_scores[1], endpoint_scores[0]
        
        # If no good match, return empty
        if not endpoint_scores or endpoint_scores[0][1] == 0:
            return {"endpoint": None, "params": {}}
        
        # Get the best matching endpoint
        best_endpoint = endpoint_scores[0][0]
        log_info(logger,f"Selected intent: {best_endpoint['name']} with score: {endpoint_scores[0][1]}")
        
        # Extract parameters (enhanced)
        params = {}
        for param in best_endpoint["params"]:
            # Look for IP addresses
            if param == "ip_address" or param == "identifier":
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
                if ip_match:
                    params[param] = ip_match.group(0)
                    continue
                    
            # Look for domains
            if param == "identifier" or param == "domain":
                domain_match = re.search(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', text)
                if domain_match:
                    params[param] = domain_match.group(0)
                    continue
            
            # Look for action IDs
            if param == "action_id":
                action_match = re.search(r'\b(?:action|task)[\s:]?([a-zA-Z0-9_-]+)\b', text)
                if action_match:
                    params[param] = action_match.group(1)
                    continue

            # Look for alert IDs
            if param == "id":
                id_match = re.search(r'\b(?:alert|id)[\s:]?([a-zA-Z0-9_-]+)\b', text)
                if id_match:
                    params[param] = id_match.group(1)
                    continue
                    
            # Look for categories
            if param == "category_name":
                cat_match = re.search(r'\b(?:category|type)[\s:]?([a-zA-Z0-9_-]+)\b', text)
                if cat_match:
                    params[param] = cat_match.group(1)
                    continue
            
            # General parameter extraction (looking for patterns like "param: value" or "param=value")
            param_match = re.search(f'{param}[:\s=]+([^\s,]+)', text)
            if param_match:
                params[param] = param_match.group(1)
        
        return {
            "endpoint": best_endpoint["name"],
            "params": params
        }
    
    def execute_api_call(self, endpoint_name, params):
        """Execute the appropriate API call and apply post-processing if needed"""
        # Find the endpoint definition
        endpoint_def = next((e for e in self.api_endpoints if e["name"] == endpoint_name), None)
        if not endpoint_def:
            return {"success": False, "message": f"Unknown endpoint: {endpoint_name}"}
        
        # Construct the URL, replacing parameter placeholders
        url = self.config.API_BASE_URL + endpoint_def["endpoint"]
        for param_name, param_value in params.items():
            if "{" + param_name + "}" in url:
                url = url.replace("{" + param_name + "}", param_value)
        
        # Make the API call
        method = endpoint_def["method"].upper()
        try:
            if method == "GET":
                response = requests.get(url)
            elif method == "POST":
                response = requests.post(url, json=params)
            elif method == "PUT":
                response = requests.put(url, json=params)
            elif method == "DELETE":
                response = requests.delete(url)
            else:
                return {"success": False, "message": f"Unsupported method: {method}"}
            
            # Handle response
            if response.status_code >= 200 and response.status_code < 300:
                try:
                    result = response.json()
                    
                    # Apply custom summarization for investigation endpoint
                    if endpoint_name == "remote_ip":
                        return self.summarize_investigation_data(result)
                    
                    # Apply custom summarization for localhost endpoint  
                    if endpoint_name == "get_localhost_by_ip":
                        return self.summarize_localhost_data(result)
                    
                    # Apply custom summarization for port service endpoint
                    if endpoint_name == "get_services_by_port":
                        return self.summarize_port_service_data(result)
                    
                    # Apply custom summarization for configuration endpoint
                    if endpoint_name == "get_configurations":
                        return self.summarize_configuration_data(result)
                    
                    # Apply custom summarization for quickstats endpoint
                    if endpoint_name == "get_statistics":
                        return self.summarize_quickstats_data(result)
                    
                    # Apply custom summarization for classification endpoint
                    if endpoint_name == "classify_device":
                        return self.summarize_classification_data(result)
                    
                    return result
                except json.JSONDecodeError:
                    return {"success": True, "message": response.text}
            else:
                return {"success": False, "message": f"API call failed with status {response.status_code}: {response.text}"}
                
        except Exception as e:
            log_error(logger,f"Error executing API call: {e}")
            return {"success": False, "message": f"Error: {str(e)}"}

    def summarize_localhost_data(self, data):
        """Create a human-readable summary of localhost data"""
        try:
            # Return both original data and a summary
            summary = ""
            
            # Basic device info
            ip = data.get("ip_address", "Unknown IP")
            hostname = data.get("dhcp_hostname", "unnamed device")
            if not hostname or hostname == "":
                hostname = "unnamed device"
            
            # Device identity
            summary += f"Device {hostname} ({ip}) "
            
            # Hardware info
            mac = data.get("mac_address", "")
            vendor = data.get("mac_vendor", "")
            if mac and vendor:
                summary += f"has MAC address {mac} (vendor: {vendor}). "
            elif mac:
                summary += f"has MAC address {mac}. "
            else:
                summary += ". "
            
            # Description
            description = data.get("local_description", "")
            if description:
                summary += f"User description: {description}. "

            first_seen = data.get("first_seen", "")

            if first_seen:
                summary += f"Device was first seen on {first_seen}.  "
            
            # If any attributes are missing, add a note
            if not summary:
                summary = f"Limited information available for device at {ip}."
            
            return {
                "original_data": data,
                "summary": summary.strip()
            }
        except Exception as e:
            log_error(logger,f"Error summarizing localhost data: {e}")
            return {
                "original_data": data,
                "summary": f"Error creating summary: {str(e)}"
            }
    
    def summarize_investigation_data(self, data):
        """Create a human-readable summary of IP investigation data"""
        try:
            # Return both original data and a summary
            summary = ""
            
            # Basic IP info
            ip = data.get("ip_address", "Unknown IP")
            dns = data.get("dns")
            country = data.get("country")
            isp = data.get("isp")
            
            # Build summary
            summary += f"IP address {ip} "
            
            if dns:
                summary += f"resolves to hostname {dns}. "
            else:
                summary += "has no reverse DNS record. "
                
            if country:
                summary += f"This IP is located in {country}. "
            else:
                summary += "The country could not be determined. "

            if isp:
                summary += f"The IP is owned by {isp}. "
                
            return {
                "original_data": data,
                "summary": summary.strip()
            }
        except Exception as e:
            log_error(logger,f"Error summarizing investigation data: {e}")
            return {
                "original_data": data,
                "summary": f"Error creating summary: {str(e)}"
            }
    
    def summarize_port_service_data(self, data):
        """Create a human-readable summary of port service data"""
        try:
            # Return both original data and a summary
            summary = ""
            port = next(iter(data.get("params", {}).values()), "unknown")
            
            if not data:
                return {
                    "original_data": data,
                    "summary": f"No service information found for port {port}."
                }
            
            summary += f"Port {port} is used by: "
            
            protocols = []
            for protocol, service in data.items():
                service_name = service.get("service_name", "unknown service")
                description = service.get("description", "")
                
                if description:
                    protocols.append(f"{service_name} ({protocol.upper()}) - {description}")
                else:
                    protocols.append(f"{service_name} ({protocol.upper()})")
            
            if protocols:
                summary += ", ".join(protocols)
            else:
                summary = f"Port {port} has no registered standard services."
                
            return {
                "original_data": data,
                "summary": summary
            }
        except Exception as e:
            log_error(logger,f"Error summarizing port service data: {e}")
            return {
                "original_data": data,
                "summary": f"Error creating summary: {str(e)}"
            }
    
    def summarize_configuration_data(self, data):
        """Create a human-readable summary of configuration data focusing on key variables"""
        try:
            # Return both original data and a summary
            summary = "System Configuration Summary:\n\n"
            
            # Convert list to dictionary if needed
            config_dict = {}
            if isinstance(data, list):
                # If data is a list of key-value pairs like [{"key": "Version", "value": "1.0"}, ...]
                for item in data:
                    if isinstance(item, dict) and "key" in item and "value" in item:
                        config_dict[item["key"]] = item["value"]
            else:
                # If data is already a dictionary
                config_dict = data
            
            # Extract key variables
            version = config_dict.get("Version", "Unknown")
            router_ip = config_dict.get("RouterIpAddress", "Not configured")
            local_networks = get_local_network_cidrs(config_dict)
            send_errors = config_dict.get("SendErrorsToCloudApi", 0)
            site_name = config_dict.get("SiteName", "Unknown Site")
            
            # Format the summary
            summary += f"• Version: {version}\n"
            summary += f"• Site Name: {site_name}\n"
            summary += f"• Router IP Address: {router_ip}\n"
            
            # Format LocalNetworks (which might be a comma-separated list)
            if local_networks:
                networks = local_networks.split(',')
                summary += f"• Local Networks: {', '.join(networks)}\n"
            else:
                summary += "• Local Networks: None configured\n"
            
            # Format SendErrorsToCloudApi as Yes/No
            send_errors_text = "Yes" if str(send_errors) == "1" else "No"
            summary += f"• Send Errors To Cloud API: {send_errors_text}\n"
            
            return {
                "original_data": data,
                "summary": summary.strip()
            }
        except Exception as e:
            log_error(logger, f"Error summarizing configuration data: {e}")
            return {
                "original_data": data,
                "summary": f"Error creating summary: {str(e)}"
            }
    
    def summarize_quickstats_data(self, data):
        """Create a human-readable summary of system quick statistics"""
        try:
            # Return both original data and a summary
            summary = "System Statistics Summary:\n\n"
            
            # Alert statistics
            total_alerts = data.get("total_alerts", 0)
            ack_alerts = data.get("acknowledged_alerts", 0)
            unack_alerts = data.get("unacknowledged_alerts", 0)
            alert_percent = 0
            if total_alerts > 0:
                alert_percent = (ack_alerts / total_alerts) * 100
                
            summary += f"• Alerts: {total_alerts} total ({ack_alerts} acknowledged, {unack_alerts} unacknowledged)\n"
            summary += f"• Alert Acknowledgment Rate: {alert_percent:.1f}%\n"
            
            # Host statistics
            total_hosts = data.get("total_localhosts_count", 0)
            ack_hosts = data.get("acknowledged_localhosts_count", 0)
            unack_hosts = data.get("unacknowledged_localhosts_count", 0)
            host_percent = 0
            if total_hosts > 0:
                host_percent = (ack_hosts / total_hosts) * 100
                
            summary += f"• Local Hosts: {total_hosts} total ({ack_hosts} acknowledged, {unack_hosts} unacknowledged)\n"
            summary += f"• Host Acknowledgment Rate: {host_percent:.1f}%\n"
            
            # IgnoreList entries
            ignorelist_count = data.get("ignorelist_count", 0)
            summary += f"• IgnoreList Entries: {ignorelist_count}\n"
            
            # System status assessment
            if unack_alerts > 10:
                summary += "\nSystem status: ATTENTION NEEDED - You have multiple unacknowledged alerts to review."
            elif unack_hosts > 5:
                summary += "\nSystem status: ACTION RECOMMENDED - You have several new hosts that need identification."
            else:
                summary += "\nSystem status: GOOD - Your system is well-maintained."
            
            return {
                "original_data": data,
                "summary": summary.strip()
            }
        except Exception as e:
            log_error(logger, f"Error summarizing quickstats data: {e}")
            return {
                "original_data": data,
                "summary": f"Error creating summary: {str(e)}"
            }
    
    def summarize_classification_data(self, data):
        """Create a human-readable summary of classification results"""
        try:
            # Return both original data and a summary
            summary = ""
            
            # Handle empty or failed classification
            if not data or "error" in data:
                error_msg = data.get("error", "Unknown error") if isinstance(data, dict) else "Classification failed"
                return {
                    "original_data": data,
                    "summary": f"Unable to classify device: {error_msg}"
                }
            
            # Get basic classification information
            device_type = data.get("device_type", "Unknown device type")
            category = data.get("category", "Unknown category")
            confidence = data.get("confidence", 0)
            
            # Format the classification summary
            summary += f"Device classified as: {device_type}\n"
            summary += f"Category: {category}\n"
            
            if confidence:
                confidence_percent = float(confidence) * 100 if isinstance(confidence, (int, float)) else confidence
                summary += f"Confidence: {confidence_percent}%\n"
            
            # Add manufacturer information if available
            manufacturer = data.get("manufacturer")
            if manufacturer:
                summary += f"Manufacturer: {manufacturer}\n"
            
            # Add any available description
            description = data.get("description")
            if description:
                summary += f"\nDescription: {description}\n"
            
            # Add any special notes or security considerations
            notes = data.get("notes")
            if notes:
                summary += f"\nNotes: {notes}\n"
                
            return {
                "original_data": data,
                "summary": summary.strip()
            }
        except Exception as e:
            log_error(logger, f"Error summarizing classification data: {e}")
            return {
                "original_data": data,
                "summary": f"Error creating classification summary: {str(e)}"
            }
    
    def process_request(self, text):
        """Process a natural language request and execute the appropriate action"""
        log_info(logger,f"Processing request: {text}")
        
        # Extract intent and parameters
        intent_result = self.extract_intent_and_params(text)
        endpoint = intent_result.get("endpoint")
        params = intent_result.get("params", {})
        
        # If no intent found, return error
        if not endpoint:
            return {"success": False, "message": "Could not determine intent from your request"}
        
        log_info(logger,f"Detected intent: {endpoint} with params: {params}")
        
        # Execute the API call
        return self.execute_api_call(endpoint, params)

# Initialize the NLP processor
nlp_processor = NLPProcessor(Config, API_ENDPOINTS)

@app.post('/api/process-request')
def process_request():
    """Process a natural language request"""
    data = request.json
    if not data or 'text' not in data:
        response.status = 400
        return {"success": False, "message": "Missing text parameter"}
    
    text = data['text']
    result = nlp_processor.process_request(text)
    return result




def start_interactive_cli():
    """Start an interactive command-line interface"""
    log_info(logger,"Starting interactive CLI mode...")
    print("\n=== NetFlowIPS AI Agent CLI ===")
    print("Type 'exit' or 'quit' to exit, 'help' for available commands.")
    
    # Start API server in a separate thread
    import threading
    server_thread = threading.Thread(
        target=lambda: run(app, host='0.0.0.0', port=5000, quiet=True),
        daemon=True
    )
    server_thread.start()
    
    while True:
        try:
            # Get user input
            user_input = input("\n> ")
            
            # Handle exit commands
            if user_input.lower() in ['exit', 'quit']:
                print("Exiting...")
                break
                
            # Handle help command
            elif user_input.lower() == 'help':
                print("\nAvailable endpoints:")
                for endpoint in API_ENDPOINTS:
                    params = ", ".join(endpoint["params"]) if endpoint["params"] else "none"
                    print(f"- {endpoint['name']}: {endpoint['description']} (Parameters: {params})")
                continue
                
            # Process the request
            if user_input.strip():
                print("\nProcessing request...")
                result = nlp_processor.process_request(user_input)
                
                # Format and display the result
                print("\n=== Result ===")
                if isinstance(result, dict):
                    if result.get("success") is False:
                        print(f"Error: {result.get('message', 'Unknown error')}")
                    else:
                        # Pretty print JSON result
                        print(json.dumps(result, indent=2))
                else:
                    print(result)
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")



if __name__ == "__main__":
    log_info(logger,"Starting NLP Agent with built-in processing only (OpenAI disabled)")
    
    # Check if we should start in CLI mode
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        start_interactive_cli()
    else:
        # Start in server mode by default
        print("Server running at http://0.0.0.0:5000/")
        print("Use --cli argument to start in CLI mode")
        run(app, host='0.0.0.0', port=5000)