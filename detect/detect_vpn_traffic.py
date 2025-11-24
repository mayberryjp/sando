
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


def detect_vpn_traffic(rows, config_dict):
    """
    Detect VPN traffic from local hosts by checking for common VPN protocols and ports.
    
    Common VPN protocols and ports:
    - OpenVPN: UDP 1194, TCP 443/1194
    - IPsec/IKE: UDP 500 (IKE), UDP 4500 (NAT-T)
    - L2TP: UDP 1701
    - PPTP: TCP 1723
    - WireGuard: UDP 51820
    - SoftEther: TCP 443, TCP 992, TCP 5555
    - Cisco AnyConnect: TCP/UDP 443
    
    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
    """
    logger = logging.getLogger(__name__)
    log_info(logger, f"[INFO] Started detecting VPN protocol usage")
    # Define VPN-related ports and protocols
    VPN_PORTS = {
        'TCP': {1194, 1723, 992, 5555},  # TCP ports (protocol 6)
        'UDP': {500, 4500, 1194, 1701, 51820}  # UDP ports (protocol 17)
    }

    VPN_PROTOCOLS = {
        47: 'GRE/PPTP',        # Generic Routing Encapsulation (PPTP)
        50: 'ESP',             # IPsec Encapsulating Security Payload
        51: 'AH',              # IPsec Authentication Header
        41: 'IPv6 Tunnel',     # IPv6 encapsulation
        97: 'ETHERIP',         # Ethernet-within-IP encapsulation
        115: 'L2TP'           # Layer 2 Tunneling Protocol
    }
    
    # Get local networks
    LOCAL_NETWORKS = get_local_network_cidrs(config_dict)
    
    # Get ignorelisted VPN servers if configured
    approved_vpn_servers = set(config_dict.get("ApprovedVpnServersList", "").split(","))
    
    vpn_flows = {}  # Track potential VPN flows by source IP
    
    for row in rows:
        src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_, *_ = row
        
        # Only check outbound connections from local networks
        if not is_ip_in_range(src_ip, LOCAL_NETWORKS):
            continue
            
        # Skip if destination is an approved VPN server
        if dst_ip in approved_vpn_servers:
            continue
        
        is_vpn = False
        proto_name = None

        # Check TCP/UDP ports
        if protocol == 6 and dst_port in VPN_PORTS['TCP']:
            is_vpn = True
            proto_name = f'TCP/{dst_port}'
        elif protocol == 17 and dst_port in VPN_PORTS['UDP']:
            is_vpn = True
            proto_name = f'UDP/{dst_port}'
        # Check VPN protocols
        elif protocol in VPN_PROTOCOLS:
            is_vpn = True
            proto_name = VPN_PROTOCOLS[protocol]

        if not is_vpn:
            continue
        
        # Create flow identifier
        alert_id = f"{src_ip}_{dst_ip}_{protocol}_{dst_port}"
        
        # Alert if this is first time seeing this flow
        alert_id = f"{alert_id}_VPNDetection"
        
        message = (f"Potential VPN Traffic Detected:\n"
                  f"Source: {src_ip}\n"
                  f"Destination: {dst_ip}:{dst_port}\n"
                  f"Protocol: {proto_name}\n")
         
        log_info(logger, f"[INFO] Potential VPN traffic detected: {src_ip} -> {dst_ip}:{dst_port} ({proto_name})")

        handle_alert(
            config_dict,
            "VpnTrafficDetection",
            message,
            src_ip,
            row,
            "Potential VPN Traffic Detected",
            dst_ip,
            f"Port:{dst_port} Proto:{proto_name}",
            alert_id
        )

    log_info(logger, f"[INFO] Finished detecting VPN protocol usage")