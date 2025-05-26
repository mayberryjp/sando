import nmap
import os
import logging
import sys
from pathlib import Path

import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *

def os_fingerprint(ip_addresses, config_dict):
    """
    Perform operating system fingerprinting for a list of IP addresses.

    Args:
        ip_addresses (list): A list of IP addresses to scan.

    Returns:
        dict: A dictionary where the keys are IP addresses and the values are the operating system fingerprint information.
    """
    logger = logging.getLogger(__name__)

    log_info(logger, f"[INFO] Nmap OS Fingerprinting starting")

    nmap_dir = r'/usr/bin'
    os.environ['PATH'] = nmap_dir + os.pathsep + os.environ['PATH']

    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError as e:
        log_error(logger, f"[ERROR] Nmap executable not found or not accessible: {e}")
        return [{"error": "Nmap executable not found or not accessible"}]
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error initializing Nmap scanner: {e}")
        return [{"error": f"Unexpected error: {e}"}]

    results = []

    for ip in ip_addresses:
        log_info(logger, f"[INFO] Scanning IP: {ip}")
        try:
            # Perform OS detection
            scan_result = scanner.scan(ip, arguments='-O')  # '-O' enables OS detection
            os_matches = scan_result['scan'].get(ip, {}).get('osmatch', [])
            
            # Extract MAC address if available
            mac_address = None
            if ip in scan_result['scan']:
                if 'addresses' in scan_result['scan'][ip]:
                    mac_address = scan_result['scan'][ip]['addresses'].get('mac')
                    if mac_address:
                        log_info(logger, f"[INFO] Found MAC address for {ip}: {mac_address}")

            if os_matches:
                # Use the highest match (first match in the list)
                best_match = os_matches[0]
                vendor = best_match.get('osclass', [{}])[0].get('vendor', 'Unknown')
                osfamily = best_match.get('osclass', [{}])[0].get('osfamily', 'Unknown')
                osgen = best_match.get('osclass', [{}])[0].get('osgen', 'Unknown')
                accuracy = best_match.get('accuracy', 'Unknown')

                results.append({
                    "ip": ip,
                    "mac_address": mac_address if mac_address else "Not available",
                    "os_fingerprint": f"{vendor}_{osfamily}_{osgen}_{accuracy}",
                })
            else:
                results.append({
                    "ip": ip,
                    "mac_address": mac_address if mac_address else "Not available",
                    "os_fingerprint": "No OS fingerprint detected",
                })
        except Exception as e:
            log_error(logger,f"[ERROR] {e}")
            pass

    log_info(logger, f"[INFO] Nmap OS fingerprinting finished")

    return results
