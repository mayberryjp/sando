import logging
import ipaddress
import json
import socket
import struct
from datetime import datetime
from ipaddress import IPv4Network
import sys
import os
import traceback
import uuid
import hashlib
from src.const import IS_CONTAINER, CONST_SITE
from src.detached import get_config_settings_detached, insert_action_detached

if (IS_CONTAINER):
    SITE = os.getenv("SITE", CONST_SITE)

def write_daily_log(message, config_dict):
    """Write a log message to a daily log file in /database/ if enabled in config."""
    try:
        if config_dict != None:
            if config_dict.get("WriteLogFile", 0) == 1:
                # Explicitly use /database/ as the log directory
                log_dir = os.path.abspath(os.path.join(os.sep, "database"))
                os.makedirs(log_dir, exist_ok=True)
                log_filename = datetime.now().strftime("%Y-%m-%d.log")
                log_path = os.path.join(log_dir, log_filename)
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(message + "\n")
    except Exception as e:
        # Fallback: print error if logging fails
        print(f"[WARN] Failed to write to daily log file: {e}")

def log_info(logger, message):
    """Log a message and print it to the console with timestamp."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    script_name = os.path.basename(sys.argv[0])
    formatted_message = f"[{timestamp}] {script_name} {message}"
    print(formatted_message)
    logger.info(formatted_message)
    config_dict = get_config_settings_detached()
    write_daily_log(formatted_message, config_dict)

def log_warn(logger, message):
    """Log a warning message and print it to the console with timestamp."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    script_name = os.path.basename(sys.argv[0])
    formatted_message = f"[{timestamp}] {script_name} {message}"
    print(formatted_message)
    logger.warning(formatted_message)
    config_dict = get_config_settings_detached()
    write_daily_log(formatted_message, config_dict)

def log_error(logger, message):
    """
    Log an error message and optionally report it to the cloud API, excluding specified messages.
    Also writes to the daily log file if enabled.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    script_name = os.path.basename(sys.argv[0])
    tb = traceback.extract_tb(sys.exc_info()[2])
    if tb:
        last_frame = tb[-1]
        file_name = os.path.basename(last_frame.filename)
        line_number = last_frame.lineno
    else:
        file_name = script_name
        line_number = "N/A"
    formatted_message = f"[{timestamp}] {script_name}[/{file_name}/{line_number}] {message}"
    print(formatted_message)
    logger.error(formatted_message)
    config_dict = get_config_settings_detached()
    write_daily_log(formatted_message, config_dict)

    excluded_messages = [
        "[ERROR] Failed to download country blocks CSV: 429",
        "[ERROR] Error updating Tor nodes: HTTPSConnectionPool(host='www.dan.me.uk', port=443): Read timed out. (read timeout=30)",
        "[ERROR] Error creating geolocation database: (\"Connection broken: ConnectionResetError(104, 'Connection reset by peer')\", ConnectionResetError(104, 'Connection reset by peer'))",
        "[ERROR] Error updating Tor nodes: HTTPSConnectionPool(host='www.dan.me.uk', port=443): Max retries exceeded with url: /torlist/?full (Caused by NewConnectionError('<urllib3.connection.HTTPSConnection object at 0x76eb94effd90>: Failed to establish a new connection: [Errno 101] Network unreachable'))",
        "[ERROR] Failed to download Tor node list: 403"

    ]

    if config_dict.get('SendErrorsToCloudApi', 0) == 1:
        if excluded_messages and any(excluded_msg in message for excluded_msg in excluded_messages):
            log_info(logger, "[INFO] Error message excluded from cloud API reporting.")
            return
        try:
            import requests
            url = f"http://api.homelabids.com:8045/api/errorreport/{config_dict['MachineUniqueIdentifier']}"
            payload = {
                "error_message": message,
                "script_name": script_name,
                "file_name": file_name,
                "timestamp": timestamp,
                "site": SITE,
                "line_number": line_number,
                "machine_unique_identifier": config_dict['MachineUniqueIdentifier']
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                log_info(logger, "[INFO] Error reported to cloud API successfully.")
            else:
                log_warn(logger, f"[WARN] Failed to report error to cloud API: {response.status_code} {url}")
        except Exception as e:
            log_warn(logger, f"[WARN] Failed to send error report to cloud API {url}: {e}")
    else:
        insert_action_detached(
            f"A fatal error occured in one of the system processes. It is suggested to turn on 'Send Errors To Cloud API' in settings in order to get these errors automatically sent to the developers. Error is as follows: [{timestamp}] {script_name}[/{file_name}/{line_number}] {message}"
        )
    if SITE == "TESTPPE":
        exit(0)


def dump_json(obj):
    """
    Convert an object to a formatted JSON string.
    
    Args:
        obj: Any JSON-serializable object
        
    Returns:
        str: Pretty-printed JSON string or error message if serialization fails
    """
    logger = logging.getLogger(__name__)
    try:
        return json.dumps(obj, indent=2, sort_keys=True, default=str)
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to serialize object to JSON: {e}")
        return str(obj)
  

def get_machine_unique_identifier():
    """
    Generate a unique identifier for the machine based on its hardware (e.g., MAC address).

    Returns:
        str: A unique identifier as a hexadecimal string.
    """
    logger = logging.getLogger(__name__)
    try:
        # Get the MAC address of the machine
        mac_address = uuid.getnode()

        if mac_address == uuid.getnode():
            log_info(logger, f"[INFO] Retrieved MAC address: {mac_address}")

        # Convert the MAC address to a hashed unique identifier
        unique_id = hashlib.sha256(str(mac_address).encode('utf-8')).hexdigest()

        log_info(logger, f"[INFO] Generated unique identifier: {unique_id}")
        return unique_id
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to generate machine unique identifier: {e}")
        return None


