#!/usr/bin/env python3
# filepath: c:\Users\rimayber\Documents\vscode_projects\homelabids\processes\sinkholedns.py

import socket
import threading
import logging
import argparse
import signal
import sys
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, RCODE

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("sinkholedns")

class SinkholeResolver:
    def __init__(self, listen_ip="0.0.0.0", port=53, ttl=60):
        """Initialize the sinkhole DNS resolver."""
        self.listen_ip = listen_ip
        self.port = port
        self.ttl = ttl
        self.udp_server = None
        self.tcp_server = None
        self.running = False
        self.stats = {
            "total_queries": 0,
            "unique_domains": set(),
            "clients": set()
        }
    
    def start(self):
        """Start the DNS server."""
        self.running = True
        
        # Start UDP server
        self.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_server.bind((self.listen_ip, self.port))
        logger.info(f"UDP DNS sinkhole listening on {self.listen_ip}:{self.port}")
        
        # Start TCP server
        self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_server.bind((self.listen_ip, self.port))
        self.tcp_server.listen(10)
        logger.info(f"TCP DNS sinkhole listening on {self.listen_ip}:{self.port}")
        
        # Start threads for handling UDP and TCP requests
        udp_thread = threading.Thread(target=self.handle_udp, daemon=True)
        udp_thread.start()
        
        tcp_thread = threading.Thread(target=self.handle_tcp, daemon=True)
        tcp_thread.start()
        
        return udp_thread, tcp_thread
    
    def stop(self):
        """Stop the DNS server."""
        logger.info("Stopping DNS sinkhole server...")
        self.running = False
        
        if self.udp_server:
            self.udp_server.close()
        
        if self.tcp_server:
            self.tcp_server.close()
        
        # Log statistics
        logger.info(f"Statistics: {self.stats['total_queries']} total queries")
        logger.info(f"Unique domains: {len(self.stats['unique_domains'])}")
        logger.info(f"Unique clients: {len(self.stats['clients'])}")
    
    def handle_udp(self):
        """Handle UDP DNS requests."""
        while self.running:
            try:
                data, addr = self.udp_server.recvfrom(1024)
                client_ip = addr[0]
                
                threading.Thread(
                    target=self.process_dns_request,
                    args=(data, client_ip, self.udp_server, addr),
                    daemon=True
                ).start()
                
            except socket.error as e:
                if self.running:
                    logger.error(f"UDP socket error: {e}")
            except Exception as e:
                logger.error(f"UDP handler error: {e}")
    
    def handle_tcp(self):
        """Handle TCP DNS requests."""
        while self.running:
            try:
                conn, addr = self.tcp_server.accept()
                client_ip = addr[0]
                
                threading.Thread(
                    target=self.process_tcp_request,
                    args=(conn, client_ip),
                    daemon=True
                ).start()
                
            except socket.error as e:
                if self.running:
                    logger.error(f"TCP socket error: {e}")
            except Exception as e:
                logger.error(f"TCP handler error: {e}")
    
    def process_tcp_request(self, conn, client_ip):
        """Process a TCP DNS request."""
        try:
            # Read message length (first 2 bytes)
            length_data = conn.recv(2)
            if len(length_data) != 2:
                return
                
            length = (length_data[0] << 8) + length_data[1]
            data = conn.recv(length)
            
            # Process the DNS request
            response = self.process_dns_request(data, client_ip)
            
            # TCP response needs length prefix
            length_bytes = len(response).to_bytes(2, byteorder='big')
            conn.send(length_bytes + response)
            
        except Exception as e:
            logger.error(f"Error processing TCP request from {client_ip}: {e}")
        finally:
            conn.close()
    
    def process_dns_request(self, data, client_ip, udp_socket=None, client_addr=None):
        """Process a DNS request and return NXDOMAIN."""
        try:
            # Parse the DNS request
            request = DNSRecord.parse(data)
            question = request.get_q()
            qname = str(question.qname)
            qtype = QTYPE[question.qtype]
            
            # Update stats
            self.stats["total_queries"] += 1
            self.stats["unique_domains"].add(qname)
            self.stats["clients"].add(client_ip)
            
            # Log the request
            logger.debug(f"Query from {client_ip}: {qname} ({qtype})")
            
            # Create NXDOMAIN response
            response = DNSRecord(
                DNSHeader(
                    id=request.header.id,
                    qr=1,  # This is a response
                    aa=0,  # Not authoritative
                    ra=0,  # Recursion not available
                    rcode=RCODE.NXDOMAIN  # Non-existent domain
                ),
                q=request.q
            )
            
            # Convert to bytes
            response_bytes = response.pack()
            
            # If this is UDP, send the response directly
            if udp_socket and client_addr:
                udp_socket.sendto(response_bytes, client_addr)
                return None
            
            # Otherwise return the response for TCP handling
            return response_bytes
            
        except Exception as e:
            logger.error(f"Error processing DNS request: {e}")
            # In case of error, send a server failure response
            if udp_socket and client_addr:
                header = DNSHeader(id=0, qr=1, rcode=RCODE.SERVFAIL)
                response = DNSRecord(header)
                udp_socket.sendto(response.pack(), client_addr)
            return None


def handle_signal(sig, frame):
    """Handle interrupt signal."""
    logger.info("Interrupt received, shutting down...")
    resolver.stop()
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple DNS Sinkhole Server")
    parser.add_argument("--ip", default="0.0.0.0", help="IP address to listen on")
    parser.add_argument("--port", type=int, default=53, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    
    # Set log level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Create and start the resolver
    resolver = SinkholeResolver(listen_ip=args.ip, port=args.port)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Start the server
    udp_thread, tcp_thread = resolver.start()
    
    logger.info("DNS Sinkhole server running. Press Ctrl+C to stop.")
    
    try:
        # Keep the main thread alive
        while True:
            signal.pause()
    except (KeyboardInterrupt, SystemExit):
        resolver.stop()