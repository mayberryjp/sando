import socket
import struct
from src.const import CONST_LINK_LOCAL_RANGE, CONST_COLLECTOR_LISTEN_ADDRESS, CONST_COLLECTOR_LISTEN_PORT, IS_CONTAINER
import os
import logging
from datetime import datetime, timezone
from src.tags import apply_tags
from queue import Queue
from init import *
import threading
import time
import json
from database.configuration import update_flow_metrics


if (IS_CONTAINER):
    COLLECTOR_LISTEN_ADDRESS=os.getenv("COLLECTOR_LISTEN_ADDRESS", CONST_COLLECTOR_LISTEN_ADDRESS)
    COLLECTOR_LISTEN_PORT=os.getenv("COLLECTOR_LISTEN_PORT", CONST_COLLECTOR_LISTEN_PORT) 

# Create global queue for netflow packets
netflow_queue = Queue()

# Update or insert flow in the DB


def parse_netflow_v5_header(data):
    # Unpack the header into its individual fields
    return struct.unpack('!HHIIIIBBH', data[:24])


def parse_netflow_v5_record(data, offset, unix_secs, uptime):
    """
    Parse a NetFlow v5 record and convert timestamps to Unix epoch format
    
    Args:
        data: The binary data containing the record
        offset: The offset where the record starts
        unix_secs: The current Unix timestamp from the header
        uptime: System uptime in milliseconds from the header
    
    Returns:
        Dictionary containing the parsed NetFlow record with proper timestamps
    """
    fields = struct.unpack('!IIIHHIIIIHHBBBBHHBBH', data[offset:offset+48])
    
    current_time = int(time.time()) # Current time in seconds since epoch
 
    return {
        'src_ip': socket.inet_ntoa(struct.pack('!I', fields[0])),
        'dst_ip': socket.inet_ntoa(struct.pack('!I', fields[1])),
        'nexthop': socket.inet_ntoa(struct.pack('!I', fields[2])),
        'input_iface': fields[3],
        'output_iface': fields[4],
        'packets': fields[5],
        'bytes': fields[6],
        'start_time': current_time,  # Store as integer epoch timestamp
        'end_time': current_time,    # Store as integer epoch timestamp
        'src_port': fields[9],
        'dst_port': fields[10],
        'tcp_flags': fields[11],
        'protocol': fields[13],
        'tos': fields[12],
        'src_as': fields[14],
        'dst_as': fields[15],
        'src_mask': fields[16],
        'dst_mask': fields[17],
        'tags': "",
        'last_seen': current_time,  # Current time as epoch instead of ISO format
        'times_seen': 1
    }

def collect_netflow_packets(listen_address, listen_port):
    """Collect packets and add them to queue"""
    logger = logging.getLogger(__name__)
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((listen_address, listen_port))
        log_info(logger, f"[INFO] NetFlow v5 collector listening on {listen_address}:{listen_port}")
        
        while True:
            try:
                data, addr = s.recvfrom(8192)
                netflow_queue.put((data, addr))
            except Exception as e:
                log_error(logger, f"[ERROR] Socket error: {e}")
                time.sleep(1)

def process_netflow_packets():
    """Process queued packets at fixed interval"""
    logger = logging.getLogger(__name__)

    while True:
        try:

            ignorelist = get_ignorelist()
            config_dict = get_config_settings()
 
            if not config_dict:
                log_error(logger, "[ERROR] Failed to load configuration settings")
                time.sleep(60)  # Wait before retry
                continue

            tag_entries_json = config_dict.get("TagEntries", "[]")
            tag_entries = []
            if tag_entries_json != "[]":
                tag_entries = json.loads(tag_entries_json)
  
            LOCAL_NETWORKS = get_local_network_cidrs(config_dict)

            # Calculate broadcast addresses for all local networks
            broadcast_addresses = set()
            if len(LOCAL_NETWORKS) > 0:
                for network in LOCAL_NETWORKS:
                    broadcast_ip = calculate_broadcast(network)
                    if broadcast_ip:
                        broadcast_addresses.add(broadcast_ip)
                broadcast_addresses.add('255.255.255.255')
                broadcast_addresses.add('0.0.0.0')
        except Exception as e:
            log_error(logger, f"[ERROR] Dependencies for collector not met {e}")

        try:
            packets = []
            # Collect all available packets
            while not netflow_queue.empty():
                packets.append(netflow_queue.get())

            last_packets = 0
            last_flows = 0
            last_bytes = 0

            if packets:
                log_info(logger, f"[INFO] Processing {len(packets)} queued packets")
                total_flows = 0
                total_bytes = 0
                total_packets = 0

                for data, addr in packets:
                    if len(data) < 24:
                        continue

                    version, count, *header_fields = parse_netflow_v5_header(data)
                    if version != 5:
                        continue

                    unix_secs = header_fields[1]
                    uptime = header_fields[2]

                    offset = 24
                    for _ in range(count):
                        if offset + 48 > len(data):
                            break

                        record = parse_netflow_v5_record(data, offset, unix_secs, uptime)
                        offset += 48

                        # Apply tags and update flow database
                        record = apply_tags(record, ignorelist, broadcast_addresses, tag_entries, config_dict, CONST_LINK_LOCAL_RANGE)
                        if config_dict.get("WriteNewFlowsToCsv", 0) == 1:
                            write_new_flow_to_csv(record)
                        update_new_flow(record)
                        total_flows += 1
                        total_bytes += record.get('bytes', 0)
                        total_packets += record.get('packets', 0)

                        if config_dict.get("WriteNewFlowsToCsv", 0) == 1:
                            write_new_flow_to_csv(record)

                log_info(logger, f"[INFO] Processed {total_flows} flows from {len(packets)} packets")

                last_flows = total_flows
                last_bytes = total_bytes
                last_packets = total_packets

            # Update flow metrics in the configuration database
            update_flow_metrics(last_packets, last_flows, last_bytes)

            # Wait for next processing interval
            interval = int(config_dict.get('CollectorProcessingInterval', 60))
            time.sleep(interval)

        except Exception as e:
            log_error(logger, f"[ERROR] Failed to process NetFlow packets: {e}")
            time.sleep(60)  # Wait before retry

def handle_netflow_v5():
    """Start collector and processor threads"""
    logger = logging.getLogger(__name__)
    
    # Start collector thread
    collector = threading.Thread(
        target=collect_netflow_packets,
        args=(COLLECTOR_LISTEN_ADDRESS, COLLECTOR_LISTEN_PORT),
        daemon=True
    )
    collector.start()
    
    # Run processor in main thread
    process_netflow_packets()

def write_new_flow_to_csv(record, filename="newflows.csv"):
    """
    Write a new flow record to a CSV file as a comma-separated string (no CSV module).
    Args:
        record (dict): The flow record to write.
        filename (str): The CSV file name.
    """
    fieldnames = [
        'src_ip', 'dst_ip', 'nexthop', 'input_iface', 'output_iface', 'packets', 'bytes',
        'start_time', 'end_time', 'src_port', 'dst_port', 'tcp_flags', 'protocol', 'tos',
        'src_as', 'dst_as', 'src_mask', 'dst_mask', 'tags', 'last_seen', 'times_seen'
    ]
    try:
        line = ",".join([str(record.get(k, "")) for k in fieldnames]) + "\n"
        # Write header if file does not exist or is empty
        if not os.path.isfile(filename) or os.path.getsize(filename) == 0:
            header = ",".join(fieldnames) + "\n"
            with open(filename, "a") as f:
                f.write(header)
        with open(filename, "a") as f:
            f.write(line)
    except Exception as e:
        logging.getLogger(__name__).error(f"[ERROR] Failed to write flow to CSV: {e}")

