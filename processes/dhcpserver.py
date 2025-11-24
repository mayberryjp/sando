import sys
import os
from pathlib import Path
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
sys.path.insert(0, "/database")
import logging
import socket
import struct
import json
from init import *

from src.locallogging import log_info, log_warn, log_error

# DHCP Message Types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8

# DHCP Options
DHCP_OPTION_PAD = 0
DHCP_OPTION_SUBNET_MASK = 1
DHCP_OPTION_ROUTER = 3
DHCP_OPTION_DNS = 6
DHCP_OPTION_HOSTNAME = 12
DHCP_OPTION_DOMAIN_NAME = 15
DHCP_OPTION_BROADCAST = 28
DHCP_OPTION_NTP = 42
DHCP_OPTION_REQUESTED_IP = 50
DHCP_OPTION_LEASE_TIME = 51
DHCP_OPTION_MESSAGE_TYPE = 53
DHCP_OPTION_SERVER_ID = 54
DHCP_OPTION_PARAMETER_LIST = 55
DHCP_OPTION_RENEWAL_TIME = 58
DHCP_OPTION_REBINDING_TIME = 59
DHCP_OPTION_CLIENT_ID = 61
DHCP_OPTION_END = 255

class DHCPServer:
    def __init__(self, server_ip, registered_devices, lease_time=86400, listen_ip='0.0.0.0', listen_port=67, enable_relay=True, scopes=None):
        """
        Initialize the DHCP server.
        Only assigns IPs to registered devices.
        
        Args:
            server_ip (str): The IP address of the DHCP server
            registered_devices (dict): MAC to IP mapping
            lease_time (int): Lease time in seconds (default 86400 = 24 hours)
            listen_ip (str): IP to bind to (default 0.0.0.0)
            listen_port (int): Port to listen on (default 67)
            enable_relay (bool): Enable DHCP relay support
            scopes (list): Optional list of subnet scopes (CIDR) for multi-subnet support
        """
        self.logger = logging.getLogger(__name__)
        
        # Server configuration
        self.server_ip = server_ip
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        
        # Network configuration
        # Single-subnet defaults (used if no scope match)
        self.subnet_mask = None
        self.router = None
        self.dns_servers = []
        self.ntp_servers = []
        self.domain_name = "homelab.local"
        # Optional multi-subnet scopes: load strictly from configuration if not provided.
        self.scopes = scopes if scopes is not None else self._load_scopes_from_configuration()
        log_info(self.logger, f"[INFO] DHCP scopes loaded: {len(self.scopes)}")
        
        # Lease configuration
        self.lease_time = lease_time
        self.renewal_time = int(lease_time * 0.5)
        self.rebinding_time = int(lease_time * 0.875)
        
        # Relay support
        self.enable_relay = enable_relay
        
        # Registered devices (MAC -> IP mapping)
        # Normalize MAC addresses to lowercase
        self.registered_devices = {mac.lower(): ip for mac, ip in registered_devices.items()}
        
        # Active leases
        self.active_leases = {}  # MAC -> {ip, hostname, expires}
        
        # Socket
        self.sock = None
        self.running = False
        
        log_info(self.logger, f"[INFO] Initialized DHCP server with {len(self.registered_devices)} registered devices")
    
    def _ip_to_bytes(self, ip):
        """Convert IP address string to bytes."""
        return socket.inet_aton(ip)
    
    def _bytes_to_ip(self, data):
        """Convert bytes to IP address string."""
        return socket.inet_ntoa(data)
    
    def _mac_to_string(self, mac_bytes):
        """Convert MAC address bytes to string."""
        return ':'.join([f'{b:02x}' for b in mac_bytes])
    
    def _parse_dhcp_packet(self, data):
        """Parse a DHCP packet."""
        if len(data) < 240:
            return None
            
        packet = {
            'op': data[0],
            'htype': data[1],
            'hlen': data[2],
            'hops': data[3],
            'xid': struct.unpack('!I', data[4:8])[0],
            'secs': struct.unpack('!H', data[8:10])[0],
            'flags': struct.unpack('!H', data[10:12])[0],
            'ciaddr': self._bytes_to_ip(data[12:16]),
            'yiaddr': self._bytes_to_ip(data[16:20]),
            'siaddr': self._bytes_to_ip(data[20:24]),
            'giaddr': self._bytes_to_ip(data[24:28]),
            'chaddr': data[28:44],
            'mac': self._mac_to_string(data[28:34]),
            'options': {}
        }
        
        # Parse options
        i = 240
        while i < len(data):
            option = data[i]
            if option == DHCP_OPTION_END:
                break
            if option == DHCP_OPTION_PAD:
                i += 1
                continue
                
            length = data[i + 1]
            value = data[i + 2:i + 2 + length]
            packet['options'][option] = value
            i += 2 + length
            
        return packet
    
    def _load_scopes_from_configuration(self):
        """
        Load scopes from configuration.db -> configuration['LocalNetworks'] as a JSON array.
        Each scope should be a dict with keys: cidr, router, ntp_servers, domain_name.
        """
        try:
            from database.configuration import get_config_settings
        except Exception:
            log_error(self.logger, "[ERROR] configuration.get_config_settings() not available; no scopes loaded")
            return []

        try:
            cfg = get_config_settings() or {}
        except Exception as e:
            log_error(self.logger, f"[ERROR] Failed to read configuration: {e}")
            return []

        raw = cfg.get("LocalNetworks")
        if not raw:
            log_warn(self.logger, "[WARN] LocalNetworks missing; no scopes will be used")
            return []

        log_info(self.logger, f"[INFO] Raw LocalNetworks JSON: {raw}")

        try:
            scopes = json.loads(raw)
            if not isinstance(scopes, list):
                log_error(self.logger, "[ERROR] LocalNetworks must be a JSON array")
                return []
        except Exception as e:
            log_error(self.logger, f"[ERROR] Could not parse LocalNetworks JSON: {e}")
            return []

        # Optionally validate/normalize each scope
        normalized = []
        for scope in scopes:
            if not isinstance(scope, dict):
                continue
            cidr = scope.get("cidr")
            router = scope.get("router")
            ntp_servers = scope.get("ntp_servers", [])
            dns_servers = scope.get("dns_servers", [])
            domain_name = scope.get("domain_name")
            lease_time = scope.get("lease_time", 86400)  # <-- NEW: get lease_time or default
            # Calculate subnet_mask from CIDR
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                subnet_mask = str(net.netmask)
            except Exception:
                log_warn(self.logger, f"[WARN] Invalid CIDR in LocalNetworks: {cidr}")
                continue
            normalized.append({
                "cidr": cidr,
                "subnet_mask": subnet_mask,
                "router": router,
                "dns_servers": dns_servers,
                "ntp_servers": ntp_servers,
                "domain_name": domain_name,
                "lease_time": lease_time,  # <-- NEW: store lease_time in scope
            })
        return normalized

    def _parse_server_list(self, value):
        """
        Parse a server list from configuration. Assumes a comma-separated string.
        Returns a list of server addresses.
        """
        if not value:
            return []
        return [s.strip() for s in value.split(",") if s.strip()]

    def _calculate_broadcast(self, ip, netmask):
        """Calculate broadcast address."""
        ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
        mask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
        broadcast_int = ip_int | (~mask_int & 0xFFFFFFFF)
        return socket.inet_ntoa(struct.pack('!I', broadcast_int))
    
    def _get_registered_ip(self, mac):
        """Get the registered IP address for a MAC address by querying the database in real time.
        If not found, insert it using insert_localhost_basic_by_mac.
        """
        mac = mac.upper()
        try:
            from database.localhosts import get_localhosts_all, insert_localhost_basic_by_mac
            hosts = get_localhosts_all()
            for h in hosts:
                if str(h.get("mac_address")).upper() == mac and h.get("ip_address"):
                    return h.get("ip_address")
            # Not found: insert new MAC
            insert_localhost_basic_by_mac(mac)
            log_info(self.logger, f"[INFO] Inserted new MAC address into localhosts database: {mac}")
        except Exception as e:
            log_error(self.logger, f"[ERROR] Could not query or insert registered devices: {e}")
        log_warn(self.logger, f"[WARN] Unregistered device attempted DHCP request: {mac}")
        return None
    
    def _resolve_scope(self, giaddr, offered_ip):
        """
        Select scope strictly by giaddr (relay) or offered_ip. No fallback.
        """
        def ip_in_cidr(ip_str, cidr_str):
            try:
                return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr_str, strict=False)
            except Exception:
                return False

        # Prefer giaddr match
        for scope in self.scopes:
            cidr = scope.get("cidr")
            if giaddr and giaddr != '0.0.0.0' and cidr and ip_in_cidr(giaddr, cidr):
                return scope

        # Otherwise use offered IP
        for scope in self.scopes:
            cidr = scope.get("cidr")
            if cidr and offered_ip and ip_in_cidr(offered_ip, cidr):
                return scope

        # No scope match
        return None

    def _build_dhcp_packet(self, message_type, request_packet, offered_ip, scope):
        """Build a DHCP response packet. For NAK, send minimal options and ignore scope."""
        response = bytearray(548)
        
        # Boot reply
        response[0] = 2
        response[1] = request_packet['htype']
        response[2] = request_packet['hlen']
        response[3] = 0  # hops
        
        # Transaction ID
        response[4:8] = struct.pack('!I', request_packet['xid'])
        
        # Seconds and flags
        response[8:10] = struct.pack('!H', 0)
        response[10:12] = struct.pack('!H', request_packet['flags'])
        
        # Client IP (only for ACK if renewing)
        if message_type == DHCP_ACK and request_packet['ciaddr'] != '0.0.0.0':
            response[12:16] = self._ip_to_bytes(request_packet['ciaddr'])
        else:
            response[12:16] = b'\x00\x00\x00\x00'
        
        # Your IP (offered IP)
        response[16:20] = self._ip_to_bytes(offered_ip)
        
        # Server IP
        response[20:24] = self._ip_to_bytes(self.server_ip)
        
        # Gateway IP (relay agent)
        response[24:28] = self._ip_to_bytes(request_packet['giaddr'])
        
        # Client hardware address
        response[28:44] = request_packet['chaddr']
        
        # Magic cookie
        response[236:240] = bytes([99, 130, 83, 99])
        
        # Options
        options = bytearray()
        options.extend([DHCP_OPTION_MESSAGE_TYPE, 1, message_type])
        options.extend([DHCP_OPTION_SERVER_ID, 4])
        options.extend(self._ip_to_bytes(self.server_ip))

        # For NAK: minimal options, no scope usage
        if message_type == DHCP_NAK:
            options.append(DHCP_OPTION_END)
            response[240:240 + len(options)] = options
            return bytes(response)

        # For OFFER/ACK: require scope; if missing, caller should not call here.
        if not scope:
            raise ValueError("Scope is required for OFFER/ACK")

        lease_time = scope.get("lease_time", 86400)  # <-- Use scope lease_time or default

        options.extend([DHCP_OPTION_LEASE_TIME, 4])
        options.extend(struct.pack('!I', lease_time))
        options.extend([DHCP_OPTION_RENEWAL_TIME, 4])
        options.extend(struct.pack('!I', int(lease_time * 0.5)))
        options.extend([DHCP_OPTION_REBINDING_TIME, 4])
        options.extend(struct.pack('!I', int(lease_time * 0.875)))

        mask = scope.get("subnet_mask")
        router = scope.get("router")
        dns_servers = scope.get("dns_servers", [])
        ntp_servers = scope.get("ntp_servers", [])
        domain_name = scope.get("domain_name")

        if mask:
            options.extend([DHCP_OPTION_SUBNET_MASK, 4])
            options.extend(self._ip_to_bytes(mask))
        if router:
            options.extend([DHCP_OPTION_ROUTER, 4])
            options.extend(self._ip_to_bytes(router))
        if dns_servers:
            dns_bytes = b''.join([self._ip_to_bytes(dns.strip()) for dns in dns_servers])
            options.extend([DHCP_OPTION_DNS, len(dns_bytes)])
            options.extend(dns_bytes)
        if ntp_servers:
            ntp_ips = []
            for ntp in ntp_servers:
                try:
                    socket.inet_aton(ntp)
                    ntp_ips.append(ntp)
                except OSError:
                    try:
                        ntp_ips.append(socket.gethostbyname(ntp))
                    except OSError:
                        log_warn(self.logger, f"[WARN] Could not resolve NTP server: {ntp}")
            if ntp_ips:
                ntp_bytes = b''.join([self._ip_to_bytes(x) for x in ntp_ips])
                options.extend([DHCP_OPTION_NTP, len(ntp_bytes)])
                options.extend(ntp_bytes)
        if domain_name:
            domain_bytes = domain_name.encode('ascii', errors='ignore')
            options.extend([DHCP_OPTION_DOMAIN_NAME, len(domain_bytes)])
            options.extend(domain_bytes)

        # Broadcast based on offered_ip + mask if mask present
        if mask:
            broadcast = self._calculate_broadcast(offered_ip, mask)
            options.extend([DHCP_OPTION_BROADCAST, 4])
            options.extend(self._ip_to_bytes(broadcast))

        options.append(DHCP_OPTION_END)
        response[240:240 + len(options)] = options
        return bytes(response)
    
    def _handle_discover(self, packet, addr):
        """Handle DHCP DISCOVER message."""
        mac = packet['mac']
        log_info(self.logger, f"[INFO] DHCP DISCOVER from {mac} via {addr}")

        assigned_ip = self._get_registered_ip(mac)
        if not assigned_ip:
            log_warn(self.logger, f"[WARN] Ignoring DISCOVER from unregistered MAC: {mac}")
            return

        scope = self._resolve_scope(packet['giaddr'], assigned_ip)
        if not scope:
            log_warn(self.logger, f"[WARN] No matching scope for giaddr={packet['giaddr']} ip={assigned_ip}; dropping DISCOVER")
            return

        offer = self._build_dhcp_packet(DHCP_OFFER, packet, assigned_ip, scope)

        # Send to relay (giaddr) or broadcast within scope
        if packet['giaddr'] and packet['giaddr'] != '0.0.0.0':
            dest_addr = (packet['giaddr'], 67)
        else:
            mask = scope.get("subnet_mask")
            bcast = self._calculate_broadcast(assigned_ip, mask) if mask else '255.255.255.255'
            dest_addr = (bcast, 68)

        try:
            self.sock.sendto(offer, dest_addr)
            log_info(self.logger, f"[INFO] Sent DHCP OFFER to {dest_addr}")
        except OSError as e:
            log_error(self.logger, f"[ERROR] Failed to send OFFER to {dest_addr}: {e}")

    def _handle_request(self, packet, addr):
        """Handle DHCP REQUEST message."""
        mac = packet['mac']
        requested_ip = None
        if DHCP_OPTION_REQUESTED_IP in packet['options']:
            requested_ip = self._bytes_to_ip(packet['options'][DHCP_OPTION_REQUESTED_IP])
        elif packet['ciaddr'] != '0.0.0.0':
            requested_ip = packet['ciaddr']

        log_info(self.logger, f"[INFO] DHCP REQUEST from {mac} for {requested_ip}")

        assigned_ip = self._get_registered_ip(mac)
        if not assigned_ip:
            log_warn(self.logger, f"[WARN] Unregistered device {mac} requested IP, sending NAK")
            nak = self._build_dhcp_packet(DHCP_NAK, packet, '0.0.0.0', None)
            try:
                dest_addr = (packet['giaddr'], 67) if packet['giaddr'] != '0.0.0.0' else ('255.255.255.255', 68)
                self.sock.sendto(nak, dest_addr)
                log_info(self.logger, f"[INFO] Sent DHCP NAK to {dest_addr}")
            except OSError as e:
                log_error(self.logger, f"[ERROR] Failed to send NAK: {e}")
            return

        if requested_ip != assigned_ip:
            log_warn(self.logger, f"[WARN] Device {mac} requested {requested_ip} but registered for {assigned_ip}; sending NAK")
            nak = self._build_dhcp_packet(DHCP_NAK, packet, '0.0.0.0', None)
            try:
                dest_addr = (packet['giaddr'], 67) if packet['giaddr'] != '0.0.0.0' else ('255.255.255.255', 68)
                self.sock.sendto(nak, dest_addr)
                log_info(self.logger, f"[INFO] Sent DHCP NAK to {dest_addr}")
            except OSError as e:
                log_error(self.logger, f"[ERROR] Failed to send NAK: {e}")
            return

        scope = self._resolve_scope(packet['giaddr'], assigned_ip)
        if not scope:
            log_warn(self.logger, f"[WARN] No matching scope for giaddr={packet['giaddr']} ip={assigned_ip}; dropping REQUEST")
            return

        ack = self._build_dhcp_packet(DHCP_ACK, packet, assigned_ip, scope)

        if packet['giaddr'] and packet['giaddr'] != '0.0.0.0':
            dest_addr = (packet['giaddr'], 67)
        else:
            mask = scope.get("subnet_mask")
            bcast = self._calculate_broadcast(assigned_ip, mask) if mask else '255.255.255.255'
            dest_addr = (bcast, 68)

        try:
            self.sock.sendto(ack, dest_addr)
            log_info(self.logger, f"[INFO] Sent DHCP ACK to {dest_addr}")
        except OSError as e:
            log_error(self.logger, f"[ERROR] Failed to send ACK to {dest_addr}: {e}")

    def _handle_release(self, packet, addr):
        """Handle DHCP RELEASE message."""
        mac = packet['mac']
        log_info(self.logger, f"[INFO] DHCP RELEASE from {mac}")
        
        if mac in self.active_leases:
            released_ip = self.active_leases[mac]['ip']
            del self.active_leases[mac]
            log_info(self.logger, f"[INFO] Released {released_ip} from {mac}")
    
    def _handle_inform(self, packet, addr):
        """Handle DHCP INFORM message."""
        mac = packet['mac']
        client_ip = packet['ciaddr']
        log_info(self.logger, f"[INFO] DHCP INFORM from {mac} at {client_ip}")
        
        # Verify this is a registered device
        assigned_ip = self._get_registered_ip(mac)
        if not assigned_ip:
            log_warn(self.logger, f"[WARN] Ignoring INFORM from unregistered MAC: {mac}")
            return

        scope = self._resolve_scope(packet['giaddr'], client_ip or assigned_ip)
        if not scope:
            log_warn(self.logger, f"[WARN] No matching scope for INFORM giaddr={packet['giaddr']} ip={client_ip}; dropping")
            return

        ack = self._build_dhcp_packet(DHCP_ACK, packet, client_ip, scope)
        try:
            if packet['giaddr'] and packet['giaddr'] != '0.0.0.0':
                self.sock.sendto(ack, (packet['giaddr'], 67))
            else:
                mask = scope.get("subnet_mask")
                bcast = self._calculate_broadcast(client_ip, mask) if mask else '255.255.255.255'
                self.sock.sendto(ack, (bcast, 68))
            log_info(self.logger, f"[INFO] Sent DHCP ACK (INFORM) for {mac}")
        except OSError as e:
            log_error(self.logger, f"[ERROR] Failed to send INFORM ACK: {e}")

    def serve_forever(self):
        """Main DHCP server loop. Interruptible by KeyboardInterrupt."""
        self.running = True
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                packet = self._parse_dhcp_packet(data)
                if not packet:
                    continue
                if DHCP_OPTION_MESSAGE_TYPE not in packet['options']:
                    continue
                msg_type = packet['options'][DHCP_OPTION_MESSAGE_TYPE][0]
                if msg_type == DHCP_DISCOVER:
                    self._handle_discover(packet, addr)
                elif msg_type == DHCP_REQUEST:
                    self._handle_request(packet, addr)
                elif msg_type == DHCP_RELEASE:
                    self._handle_release(packet, addr)
                elif msg_type == DHCP_INFORM:
                    self._handle_inform(packet, addr)
            except Exception as e:
                log_error(self.logger, f"[ERROR] Error processing DHCP packet: {e}")

    def start(self):
        """Start the DHCP server and bind socket."""
        log_info(self.logger, "[INFO] Starting DHCP server (registered devices only)...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind((self.listen_ip, self.listen_port))
            log_info(self.logger, f"[INFO] DHCP server listening on {self.listen_ip}:{self.listen_port}")
            log_info(self.logger, f"[INFO] Server IP: {self.server_ip}")
            log_info(self.logger, f"[INFO] Registered Devices: {len(self.registered_devices)}")
            log_info(self.logger, f"[INFO] Relay Support: {self.enable_relay}")
            for mac, ip in self.registered_devices.items():
                log_info(self.logger, f"[INFO] Registered: {mac} -> {ip}")
            log_info(self.logger, "[INFO] Known DHCP scopes:")
            for scope in self.scopes:
                log_info(
                    self.logger,
                    f"[INFO] Scope: CIDR={scope.get('cidr')}, "
                    f"Mask={scope.get('subnet_mask')}, "
                    f"Router={scope.get('router')}, "
                    f"Domain={scope.get('domain_name')}"
                )
        except Exception as e:
            log_error(self.logger, f"[ERROR] Failed to start DHCP server: {e}")
            self.stop()
            raise

    def stop(self):
        """Stop the DHCP server."""
        log_info(self.logger, "[INFO] Stopping DHCP server...")
        self.running = False
        if self.sock:
            self.sock.close()
        log_info(self.logger, "[INFO] DHCP server stopped")


if __name__ == "__main__":
    try:
        from database.configuration import get_config_settings
        cfg = get_config_settings() or {}
    except Exception as e:
        log_error(logging.getLogger(__name__), f"[ERROR] Could not load configuration: {e}")
        cfg = {}

    # Get registered devices from localhosts database
    try:
        from database.localhosts import get_localhosts_all
        hosts = get_localhosts_all()
        # Build MAC -> IP mapping (lowercase MAC)
        registered_devices = {
            str(h.get("mac_address")).upper(): h.get("ip_address")
            for h in hosts
            if h.get("mac_address") and h.get("ip_address")
        }
        log_info(logging.getLogger(__name__), f"[INFO] Loaded {len(registered_devices)} registered devices from localhosts database")
    except Exception as e:
        log_error(logging.getLogger(__name__), f"[ERROR] Could not load registered devices from localhosts database: {e}")
        registered_devices = {}

    server = DHCPServer(
        server_ip='10.2.50.2',
        registered_devices={},  # Not used, but required by constructor
        lease_time=86400,
        listen_ip='0.0.0.0',
        listen_port=67,
        scopes=None
    )

    try:
        server.start()
        server.serve_forever()
    except KeyboardInterrupt:
        log_info(logging.getLogger(__name__), "[INFO] KeyboardInterrupt received, shutting down DHCP server.")
        server.stop()