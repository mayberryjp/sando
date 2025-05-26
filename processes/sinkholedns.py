import sys
import os
from pathlib import Path
import time
import threading
import queue
import datetime
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
sys.path.insert(0, "/database")
from init import *
import socket
import threading
import logging
import signal
import sys
import os
from pathlib import Path
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, RCODE
from src.locallogging import log_info, log_warn, log_error

# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import the database functions
from database.pihole import insert_pihole_query, insert_pihole_queries_batch

class SinkholeResolver:
    def __init__(self, listen_ip="0.0.0.0", port=53, ttl=60, batch_interval_minutes=29):
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
        
        # Query queue for batch processing
        self.query_queue = []
        self.query_lock = threading.Lock()
        self.batch_interval = batch_interval_minutes * 60  # Convert to seconds
        self.last_batch_time = time.time()
        
    def start(self):
        """Start the DNS server."""
        self.running = True
        logger = logging.getLogger(__name__)
        
        # Start UDP server
        self.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_server.bind((self.listen_ip, self.port))
        log_info(logger, f"[INFO] UDP DNS sinkhole listening on {self.listen_ip}:{self.port}")
        
        # Start TCP server
        self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_server.bind((self.listen_ip, self.port))
        self.tcp_server.listen(10)
        log_info(logger, f"[INFO] TCP DNS sinkhole listening on {self.listen_ip}:{self.port}")
        
        # Start threads for handling UDP and TCP requests
        udp_thread = threading.Thread(target=self.handle_udp, daemon=True)
        udp_thread.start()
        
        tcp_thread = threading.Thread(target=self.handle_tcp, daemon=True)
        tcp_thread.start()
        
        # Start database batch writer thread
        batch_thread = threading.Thread(target=self.batch_writer, daemon=True)
        batch_thread.start()
        log_info(logger, f"[INFO] Started batch writer thread (interval: {self.batch_interval//60} minutes)")
        
        return udp_thread, tcp_thread
    
    def stop(self):
        """Stop the DNS server."""
        logger = logging.getLogger(__name__)
        log_info(logger, "[INFO] Stopping DNS sinkhole server...")
        self.running = False
        
        # Process any remaining entries in the queue
        self.process_queue(force=True)
        
        if self.udp_server:
            self.udp_server.close()
        
        if self.tcp_server:
            self.tcp_server.close()
            
        # Log statistics
        log_info(logger, f"[INFO] Statistics: {self.stats['total_queries']} total queries")
        log_info(logger, f"[INFO] Unique domains: {len(self.stats['unique_domains'])}")
        log_info(logger, f"[INFO] Unique clients: {len(self.stats['clients'])}")
    
    def batch_writer(self):
        """Thread that writes queued DNS queries to database at regular intervals."""
        logger = logging.getLogger(__name__)
        log_info(logger, "[INFO] Batch writer thread started")
        
        while self.running:
            # Sleep for a short interval and check if it's time to process
            time.sleep(10)
            current_time = time.time()
            
            # Check if it's time to process the queue
            if current_time - self.last_batch_time >= self.batch_interval:
                # Pass force=True to ensure processing happens regardless of queue size
                self.process_queue(force=True)
                self.last_batch_time = current_time
                log_info(logger, f"[INFO] Performed scheduled batch processing after {self.batch_interval//60} minutes")
    
    def process_queue(self, force=False):
        logger = logging.getLogger(__name__)
        
        with self.query_lock:
            queue_size = len(self.query_queue)
            if queue_size == 0:
                return
                
            if not force and queue_size < 100:  # Only process if we have enough entries or forced
                return
                
            # Make a copy of the queue and clear it
            current_batch = self.query_queue.copy()
            self.query_queue = []
        
        # Process the batch outside of the lock
        if current_batch:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_info(logger, f"[INFO] Writing batch of {len(current_batch)} DNS queries to database")
            
            try:
                # If you have a batch insert function, use it here
                # Otherwise, iterate through and insert individually
                success_count = 0
                error_count = 0
                
                # Check if batch insert function exists
                if hasattr(sys.modules['database.pihole'], 'insert_pihole_queries_batch'):
                    # Use batch insert
                    success, count = insert_pihole_queries_batch(current_batch)
                    if success:
                        success_count = count
                    else:
                        error_count = len(current_batch)
                else:
                    # Fall back to individual inserts
                    for query in current_batch:
                        if insert_pihole_query(query['client_ip'], query['domain'], query['blocked']):
                            success_count += 1
                        else:
                            error_count += 1
                
                log_info(logger, f"[INFO] Batch processing complete. Success: {success_count}, Errors: {error_count}")
                
            except Exception as e:
                log_error(logger, f"[ERROR] Error processing batch: {e}")
    
    def handle_udp(self):
        logger = logging.getLogger(__name__)
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
                    log_error(logger, f"[ERROR] UDP socket error: {e}")
            except Exception as e:
                log_error(logger, f"[ERROR] UDP handler error: {e}")
    
    def handle_tcp(self):
        """Handle TCP DNS requests."""
        logger = logging.getLogger(__name__)
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
                    log_error(logger, f"[ERROR] TCP socket error: {e}")
            except Exception as e:
                log_error(logger, f"[ERROR] TCP handler error: {e}")
    
    def process_tcp_request(self, conn, client_ip):
        """Process a TCP DNS request."""
        logger = logging.getLogger(__name__)
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
            log_error(logger, f"[ERROR] Error processing TCP request from {client_ip}: {e}")
        finally:
            conn.close()
    
    def process_dns_request(self, data, client_ip, udp_socket=None, client_addr=None):
        """Process a DNS request and return NXDOMAIN."""
        logger = logging.getLogger(__name__)
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
            
            # Clean up domain name (remove trailing dot)
            domain = qname.rstrip('.')
            
            # Instead of writing to the database immediately, add to the queue
            with self.query_lock:
                self.query_queue.append({
                    'client_ip': client_ip,
                    'domain': domain,
                    'blocked': 1,  # Always blocked since this is a sinkhole
                    'timestamp': time.time()
                })
            
            # Check if we should force a queue processing due to size
            if len(self.query_queue) >= 10000:  # Process when queue gets very large
                # Start a separate thread for processing to avoid blocking the DNS server
                threading.Thread(target=self.process_queue, kwargs={'force': True}, daemon=True).start()
            
            # Log the request (limit frequency of logging to avoid overwhelming logs)
            if self.stats["total_queries"] % 100 == 0:
                log_info(logger, f"[INFO] Processed {self.stats['total_queries']} queries (last: {client_ip}: {qname})")
            
            log_info(logger,f"[INFO] DNS request processed from {client_ip} for domain {qname} of type {qtype}")
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
            log_error(logger, f"[ERROR] Error processing DNS request: {e}")
            # In case of error, send a server failure response
            if udp_socket and client_addr:
                header = DNSHeader(id=0, qr=1, rcode=RCODE.SERVFAIL)
                response = DNSRecord(header)
                udp_socket.sendto(response.pack(), client_addr)
            return None


def handle_signal(sig, frame):
    """Handle interrupt signal."""
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Interrupt received, shutting down...")
    resolver.stop()
    sys.exit(0)


if __name__ == "__main__":
    # Create and start the resolver
    logger = logging.getLogger(__name__)
    config_dict = get_config_settings()
    if not config_dict:
        log_error(logging(__name__), "[ERROR] Failed to load configuration settings")

    if not config_dict.get('SinkHoleDns', 0):
        log_info(logging, "[INFO] Sinkhole DNS is disabled in configuration. Exiting.")
    else:
        resolver = SinkholeResolver(listen_ip="0.0.0.0", port=53)

        
        # Set up signal handlers
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        
        # Start the server
        udp_thread, tcp_thread = resolver.start()
        
        log_info(logger, "[INFO] DNS Sinkhole server running. Press Ctrl+C to stop.")
    
    # Keep the main thread alive with a cross-platform solution
    while True:
        time.sleep(1)  # Sleep for 1 second
