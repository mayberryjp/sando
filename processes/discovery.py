import sys
from pathlib import Path
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
sys.path.insert(0, "/database")
import time
import logging
from integrations.dns import dns_lookup  # Import the dns_lookup function from dns.py
from integrations.piholedhcp import get_pihole_dhcp_leases, get_pihole_network_devices
from integrations.nmap_fingerprint import os_fingerprint
from integrations.threatscore import calculate_update_threat_scores

from init import *

def do_discovery():
    logger = logging.getLogger(__name__)

    config_dict = get_config_settings()

    if not config_dict:
        log_error(logger, "[ERROR] Failed to load configuration settings")
        return

    if config_dict.get("EnableLocalDiscoveryProcess", 0) < 1:
        log_info(logger, "[INFO] Discovery process is not enabled so stopping here.")
        return

    existing_localhosts = get_localhosts()

    log_info(logger,"[INFO] Threat score calculation started")
    calculate_update_threat_scores()
    log_info(logger,"[INFO] Threat score calculation finished")
    
    combined_results = {}
    
    DNS_SERVERS = config_dict['ApprovedLocalDnsServersList'].split(',')

    if DNS_SERVERS and config_dict.get('DiscoveryReverseDns', 0) > 0:
        dns_results = dns_lookup(existing_localhosts, DNS_SERVERS, config_dict)
        for result in dns_results:
            ip = result["ip"]
            combined_results[ip] = {
                "dns_hostname": result.get("dns_hostname", None),
            }
    else:
        log_error(logger, "[ERROR] No DNS servers in configuration to perform DNS lookup or DnsDiscoveryNotEnabled")


    if config_dict.get('DiscoveryPiholeDhcp', 0) > 0:
        nd_results = get_pihole_network_devices(existing_localhosts, config_dict)
        # Process DHCP results
        for result in nd_results:
            ip = result["ip"]
            if ip not in combined_results:
                combined_results[ip] = {}
            combined_results[ip].update({
                "dhcp_hostname": result.get("dhcp_hostname", combined_results[ip].get("dhcp_hostname")),
                "mac_address": result.get("mac_address", combined_results[ip].get("mac_address")),
                "mac_vendor": result.get("mac_vendor", combined_results[ip].get("mac_vendor")),
            })

        dl_results = get_pihole_dhcp_leases(existing_localhosts, config_dict)
        # Process DHCP results
        for result in dl_results:
            ip = result["ip"]
            if ip not in combined_results:
                combined_results[ip] = {}
            combined_results[ip].update({
                "lease_hostname": result.get("lease_hostname", combined_results[ip].get("lease_hostname")),
                "lease_hwaddr": result.get("lease_hwaddr", combined_results[ip].get("lease_hwaddress")),
                "lease_clientid": result.get("lease_clientid", combined_results[ip].get("lease_clientid")),
            })

    if config_dict.get('DiscoveryNmapOsFingerprint', 0) > 0:
        nmap_results = os_fingerprint(existing_localhosts, config_dict)
        for result in nmap_results:
            ip = result["ip"]
            if ip not in combined_results:
                combined_results[ip] = {}
            
            # Update OS fingerprint information
            combined_results[ip].update({
                "os_fingerprint": result.get("os_fingerprint", combined_results[ip].get("os_fingerprint")),
            })
            
            # Check if we have a mac_address from nmap and if the current mac_address is empty or "Not available"
            nmap_mac = result.get("mac_address")
            if nmap_mac and nmap_mac != "Not available":
                current_mac = combined_results[ip].get("mac_address")
                # Only use the nmap MAC if we don't already have one from Pihole
                if not current_mac or current_mac == "Not available":
                    log_info(logger, f"[INFO] Using Nmap-discovered MAC address for {ip}: {nmap_mac}")
                    combined_results[ip]["mac_address"] = nmap_mac

    # Update the localhosts database
    for ip, data in combined_results.items():
        update_localhosts(
            ip,  # identifier (IP or MAC)
            mac_vendor=data.get("mac_vendor"),
            dhcp_hostname=data.get("dhcp_hostname"),
            dns_hostname=data.get("dns_hostname"),
            os_fingerprint=data.get("os_fingerprint"),
            lease_hostname=data.get("lease_hostname"),
            lease_hwaddr=data.get('lease_hwaddr'),
            lease_clientid=data.get('lease_clientid')
        )

    log_info(logger,"[INFO] Discovery process completed.")

if __name__ == "__main__":
    # wait a bit for startup so collector can init configurations

    STARTUP_DELAY = 180
    logger = logging.getLogger(__name__)
    log_info(logger,f"[INFO] Pausing discovery process for {STARTUP_DELAY} seconds at startup")
    time.sleep(STARTUP_DELAY)
    config_dict = get_config_settings()
    if not config_dict:
        log_error(logger, "[ERROR] Failed to load configuration settings")
        exit(1)

    log_info(logger, f"[INFO] Discovery process started.")

    DISCOVERY_RUN_INTERVAL = config_dict.get("DiscoveryProcessRunInterval", 22800)  # Default to 60 seconds if not set

    while True:
        do_discovery()
        time.sleep(DISCOVERY_RUN_INTERVAL)

