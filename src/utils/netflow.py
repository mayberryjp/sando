import os
import socket
import struct
import time
from queue import Queue

from src.const import CONST_COLLECTOR_LISTEN_ADDRESS, CONST_COLLECTOR_LISTEN_PORT
from src.utils.flow_collector import run_flow_collector, write_new_flow_to_csv as write_new_flow_to_csv

COLLECTOR_LISTEN_ADDRESS = os.getenv(
    "COLLECTOR_LISTEN_ADDRESS", CONST_COLLECTOR_LISTEN_ADDRESS
)
COLLECTOR_LISTEN_PORT = int(os.getenv(
    "COLLECTOR_LISTEN_PORT", CONST_COLLECTOR_LISTEN_PORT
))
netflow_queue = Queue()


def parse_netflow_v5_header(data):
    return struct.unpack("!HHIIIIBBH", data[:24])


def parse_netflow_v5_record(data, offset, unix_secs, uptime):
    fields = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", data[offset:offset + 48])
    current_time = int(time.time())
    return {
        "src_ip": socket.inet_ntoa(struct.pack("!I", fields[0])),
        "dst_ip": socket.inet_ntoa(struct.pack("!I", fields[1])),
        "nexthop": socket.inet_ntoa(struct.pack("!I", fields[2])),
        "input_iface": fields[3],
        "output_iface": fields[4],
        "packets": fields[5],
        "bytes": fields[6],
        "start_time": current_time,
        "end_time": current_time,
        "src_port": fields[9],
        "dst_port": fields[10],
        "tcp_flags": fields[12],
        "protocol": fields[13],
        "tos": fields[14],
        "src_as": fields[15],
        "dst_as": fields[16],
        "src_mask": fields[17],
        "dst_mask": fields[18],
        "tags": "",
        "last_seen": current_time,
        "times_seen": 1,
    }


def parse_netflow_v5_packet(data, addr, received_at=None):
    if len(data) < 24:
        raise ValueError("Truncated NetFlow v5 header")
    version, count, uptime, unix_secs, *_ = parse_netflow_v5_header(data)
    if version != 5:
        raise ValueError(f"Expected NetFlow v5, got version {version}")
    if len(data) < 24 + count * 48:
        raise ValueError("Truncated NetFlow v5 records")
    records = [
        parse_netflow_v5_record(data, 24 + index * 48, unix_secs, uptime)
        for index in range(count)
    ]
    if received_at is not None:
        for record in records:
            for field in ("start_time", "end_time", "last_seen"):
                record[field] = int(received_at)
    return records


def handle_netflow_v5():
    run_flow_collector(
        COLLECTOR_LISTEN_ADDRESS, COLLECTOR_LISTEN_PORT,
        parse_netflow_v5_packet, "NetFlow v5", "netflow", netflow_queue,
    )
