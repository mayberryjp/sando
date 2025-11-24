

import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
import time
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
from locallogging import log_info, log_error, log_warn
from notifications.core import handle_alert
from init import *

def detect_high_risk_ports(rows, config_dict):
    """
    Detect traffic from local networks to high-risk destination ports.
    Common high-risk ports include:
    - 135: MSRPC
    - 137-139: NetBIOS
    - 445: SMB
    - 25/587: SMTP
    - 22: SSH
    - 23: Telnet
    - 3389: RDP
    
    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger,"[INFO] Started detecting high risk ports")
    # Get high-risk ports from config
    high_risk_ports = set(
        int(port.strip()) 
        for port in config_dict.get("HighRiskPorts", "135,137,138,139,445,25,587,22,23,3389").split(",")
        if port.strip()
    )
    
    # Get local networks
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)
    
    # Get ignorelisted destinations if configured
    approved_destinations = set(config_dict.get("ApprovedHighRiskDestinations", "").split(","))
    
    total = len(rows)
    matches = 0
    
    for row in rows:
        src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_, *_ = row
        
        # Only check outbound connections from local networks
        if not is_ip_in_range(src_ip, LOCAL_NETWORKS):
            continue
            
        # Skip if destination is approved
        if dst_ip in approved_destinations:
            continue
        
        # Check if destination port is in high-risk list
        if dst_port in high_risk_ports:
            matches += 1
            
            service_name = {
                135: "MSRPC",
                137: "NetBIOS",
                138: "NetBIOS",
                139: "NetBIOS",
                445: "SMB",
                25: "SMTP",
                587: "SMTP",
                22: "SSH",
                23: "Telnet",
                3389: "RDP"
            }.get(dst_port, "Unknown")
            
            alert_id = f"{src_ip}_{dst_ip}_{protocol}_{dst_port}_HighRiskPort"
            
            message = (f"High-Risk Port Traffic Detected:\n"
                      f"Source: {src_ip}\n"
                      f"Destination: {dst_ip}:{dst_port}\n"
                      f"Service: {service_name}\n"
                      f"Protocol: {protocol}\n"
                      f"Packets: {packets}")
            
            log_info(logger, f"[INFO] High-risk port traffic detected: {src_ip} -> {dst_ip}:{dst_port} ({service_name})")
            
            handle_alert(
                config_dict,
                "HighRiskPortDetection",
                message,
                src_ip,
                row,
                "High-Risk Port Traffic Detected",
                dst_ip,
                f"Port:{dst_port} ({service_name})",
                alert_id
            )
    
    log_info(logger, f"[INFO] Completed high-risk port detection. Found {matches} matches in {total} flows")

