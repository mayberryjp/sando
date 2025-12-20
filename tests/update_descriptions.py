import os
import sys
from pathlib import Path

# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def update_localhosts(data_object):
    """
    Updates local host information using the /api/localhosts/<ip_address> endpoint.

    Args:
        data_object (list): A list of dictionaries, each containing:
            - api_endpoint (str): The API endpoint URL.
            - ip_address (str): The IP address of the device.
            - category (str): The device category (used as the icon).
            - local_description (str): The local description of the device.
    """

    logger = logging.getLogger(__name__)
    log_info(
        logger,
        f"[INFO] Starting update_localhosts with data_object: {len(data_object)}",
    )
    for entry in data_object:
        api_endpoint = entry.get("api_endpoint")
        ip_address = entry.get("ip_address")
        category = entry.get("category")
        local_description = entry.get("local_description")
        log_info(logger, f"[INFO] Processing entry: {ip_address}")

        # log_info(logger,f"[INFO] Processing entry: {dump_json(entry)}")
        if not api_endpoint or not ip_address or not category or not local_description:
            logger.error(f"Missing required parameters in entry: {entry}")
            continue

        # Construct the PUT URL and JSON body
        put_url = f"{api_endpoint}/api/localhosts/{ip_address}"
        json_body = {
            "local_description": local_description,
            "icon": category,  # Use the category as the icon
            "acknowledged": 1,
        }

        try:
            # Perform the PUT request
            logger.info(f"[INFO] Updating local host: {ip_address} at {put_url}")
            put_response = requests.put(put_url, json=json_body, timeout=10)
            put_response.raise_for_status()

            if put_response.status_code == 200:
                logger.info(f"[INFO] Successfully updated local host: {ip_address}")
            else:
                logger.error(
                    f"[ERROR] Failed to update local host: {ip_address}, Status Code: {put_response.status_code}"
                )
                continue

            # Perform the GET request to fetch the entire host list
            get_url = f"{api_endpoint}/api/localhosts"
            logger.info(
                f"Fetching the entire host list to verify update for local host: {ip_address}"
            )

            get_response = requests.get(get_url, timeout=10)
            get_response.raise_for_status()
            log_info(logger, f"Retrieving host list from: {get_url}")

            if get_response.status_code == 200:
                all_hosts = get_response.json()
                # Filter the specific host by IP address
                updated_host = next(
                    (
                        host
                        for host in all_hosts
                        if host.get("ip_address") == ip_address
                    ),
                    None,
                )

                if updated_host:
                    if (
                        updated_host.get("local_description") == local_description
                        and updated_host.get("icon") == category
                    ):
                        log_info(
                            logger,
                            f"Verification successful for local host: {ip_address}",
                        )
                    else:
                        pass
                        # log_error(logger,f"Verification failed for local host: {ip_address}. Data mismatch. Expected {local_description} got {updated_host.get("local_description")} and {category} got {updated_host.get("icon")}")
                else:
                    log_warn(
                        logger, f"Host with IP {ip_address} not found in the host list."
                    )
            else:
                log_error(
                    logger,
                    f"Failed to fetch the host list for verification, Status Code: {get_response.status_code}",
                )

        except requests.exceptions.RequestException as e:
            log_error(
                logger,
                f"Error while updating or verifying local host: {ip_address}, Error: {e}",
            )


if __name__ == "__main__":
    # Example data object
    from tests.local_descriptions_object import LOCAL_DESCRIPTIONS

    # Call the function with the example data object
    update_localhosts(LOCAL_DESCRIPTIONS)
