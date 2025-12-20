import ipaddress
import logging
import socket
import struct
from ipaddress import IPv4Network

from src.utils.locallogging import log_error, log_info, log_warn


def is_ip_in_range(ip, ranges):
    """Check if an IP address is within the specified ranges."""
    logger = logging.getLogger(__name__)
    try:
        for ip_range in ranges:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                return True
        return False
    except ValueError as e:
        log_error(logger, f"[ERROR] Invalid IP address or range: {e}")
        return False


def ip_network_to_range(network):
    logger = logging.getLogger(__name__)
    """
    Convert a CIDR network to start and end IP addresses as integers using inet_aton.

    Args:
        network (str): Network in CIDR notation (e.g., '192.168.1.0/24')

    Returns:
        tuple: (start_ip, end_ip, netmask) as integers
    """
    try:
        net = IPv4Network(network)
        # Convert IP addresses to integers using inet_aton and struct.unpack
        start_ip = struct.unpack("!L", socket.inet_aton(str(net.network_address)))[0]
        end_ip = struct.unpack("!L", socket.inet_aton(str(net.broadcast_address)))[0]
        netmask = struct.unpack("!L", socket.inet_aton(str(net.netmask)))[0]

        return start_ip, end_ip, netmask
    except Exception as e:
        log_warn(logger, f"[WARN] Invalid network format {network}: {e}")
        return None, None, None


def ip_to_int(ip_addr):
    """Convert an IP address to an integer using inet_aton."""
    try:
        return struct.unpack("!L", socket.inet_aton(ip_addr))[0]
    except:
        return None


def get_usable_ips(networks):
    """
    Get a list of all usable IP addresses for multiple network ranges.

    Args:
        networks (list): A list of networks in CIDR notation (e.g., ['192.168.1.0/24', '10.0.0.0/8']).

    Returns:
        dict: A dictionary where the keys are the networks and the values are lists of usable IP addresses.
    """
    logger = logging.getLogger(__name__)
    results = {}

    for network in networks:
        try:
            net = IPv4Network(network, strict=False)
            # Exclude the network address and broadcast address
            usable_ips = [str(ip) for ip in net.hosts()]
            results[network] = usable_ips
            log_info(
                logger,
                f"[INFO] Found {len(usable_ips)} usable IPs in network {network}",
            )
        except ValueError as e:
            log_error(logger, f"[ERROR] Invalid network format {network}: {e}")
            results[network] = []

    return results


def calculate_broadcast(network_cidr):
    """
    Calculate broadcast address from CIDR notation.

    Args:
        network_cidr (str): Network in CIDR notation (e.g., '192.168.1.0/24')

    Returns:
        str: Broadcast address or None if invalid input

    Example:
        >>> calculate_broadcast('192.168.1.0/24')
        '192.168.1.255'
        >>> calculate_broadcast('10.0.0.0/8')
        '10.255.255.255'
    """
    logger = logging.getLogger(__name__)
    try:
        # Parse CIDR notation
        network = ipaddress.IPv4Network(network_cidr, strict=False)
        broadcast = str(network.broadcast_address)

        # log_info(logger, f"[INFO] Calculated broadcast {broadcast} for network {network_cidr}")
        return broadcast

    except ValueError as e:
        log_error(logger, f"[ERROR] Invalid CIDR format {network_cidr}: {e}")
        return None
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to calculate broadcast address: {e}")
        return None
