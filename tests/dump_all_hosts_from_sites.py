import os
import requests
import json
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Folder to save client definitions
OUTPUT_FOLDER = "tests\client_definitions/"

def fetch_localhosts(api_url):
    """
    Fetch the list of localhost data from the /api/localhosts endpoint.

    Args:
        api_url (str): The base URL of the API.

    Returns:
        list: A list of IP addresses extracted from the localhost data.
    """
    try:
        response = requests.get(f"{api_url}/api/localhosts", timeout=10)
        response.raise_for_status()
        localhost_data = response.json()
        ip_addresses = [entry["ip_address"] for entry in localhost_data if "ip_address" in entry]
        print(f"Fetched {len(ip_addresses)} IP addresses from {api_url}/api/localhosts")
        return ip_addresses
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch localhost data from {api_url}: {e}")
        return []

def fetch_client_data(api_url, ip_address):
    """
    Fetch client data for a specific IP address.

    Args:
        api_url (str): The base URL of the API.
        ip_address (str): The IP address to query.

    Returns:
        dict: The client data returned by the API.
    """
    try:
        response = requests.get(f"{api_url}/api/client/{ip_address}", timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch client data for {ip_address} from {api_url}: {e}")
        return None

def save_client_data(ip_address, data):
    """
    Save client data to a JSON file.

    Args:
        ip_address (str): The IP address used as the filename.
        data (dict): The client data to save.
    """
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)

    file_path = os.path.join(OUTPUT_FOLDER, f"{ip_address}.json")
    try:
        with open(file_path, "w") as file:
            json.dump(data, file, indent=4)
        print(f"Saved client data for {ip_address} to {file_path}")
    except IOError as e:
        logging.error(f"Failed to save client data for {ip_address}: {e}")

def main():


    # Array of API base URLs
    api_urls = [
        "http://192.168.50.220:8044",
        "http://192.168.230.236:8044",
        "http://192.168.60.4:8044"
    ]

    # Loop through each API URL
    for api_url in api_urls:
        print(f"Processing API URL: {api_url}")

        # Step 1: Fetch localhost data
        ip_addresses = fetch_localhosts(api_url)

        # Step 2: Loop through each IP address and fetch client data
        for ip_address in ip_addresses:
            print(f"Fetching client data for IP: {ip_address} from {api_url}")
            client_data = fetch_client_data(api_url, ip_address)
            if client_data:
                # Step 3: Save the client data to a file
                save_client_data(ip_address, client_data)

if __name__ == "__main__":
    print ("starting main")
    main()