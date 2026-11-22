import ipaddress
import json
import logging
import os
import socket
import sqlite3
import struct
import threading
import time
from datetime import datetime
from queue import Empty, Queue

from src.const import CONST_LINK_LOCAL_RANGE
from src.database.configuration import (
    get_config_settings,
    get_local_network_cidrs,
    update_flow_metrics,
)
from src.database.ignorelist import get_ignorelist
from src.database.localhosts import update_localhost_stats
from src.database.newflows import update_new_flows
from src.utils.locallogging import log_error, log_info, log_warn
from src.utils.network import calculate_broadcast
from src.utils.tags import apply_tags


def collect_flow_packets(listener, packet_queue, stop_event, name, receiver_failed):
    logger = logging.getLogger(__name__)
    while not stop_event.is_set():
        try:
            data, addr = listener.recvfrom(65535)
            packet_queue.put((data, addr, time.time()))
        except socket.timeout:
            continue
        except OSError as exc:
            if not stop_event.is_set():
                log_error(logger, f"[ERROR] {name} socket error: {exc}")
                receiver_failed.set()
                stop_event.set()
            return


def process_flow_batch(packets, parse_packet, name, source, config_dict, ignorelist):
    logger = logging.getLogger(__name__)
    tag_entries = json.loads(config_dict.get("TagEntries", "[]"))
    local_networks = [
        ipaddress.ip_network(cidr)
        for cidr in get_local_network_cidrs(config_dict)
    ]
    broadcast_addresses = {
        calculate_broadcast(str(network))
        for network in local_networks
        if network.version == 4
    }
    if any(network.version == 4 for network in local_networks):
        broadcast_addresses.update(("255.255.255.255", "0.0.0.0"))

    records = []
    ip_stats = {}
    total_packets = total_bytes = 0
    datagram_count = 0
    for packet in packets:
        datagram_count += 1
        try:
            decoded = parse_packet(*packet)
        except (ValueError, struct.error) as exc:
            log_warn(logger, f"[WARN] Invalid {name} packet from {packet[1]}: {exc}")
            continue
        for record in decoded:
            record = apply_tags(
                record, ignorelist, broadcast_addresses, tag_entries,
                config_dict, CONST_LINK_LOCAL_RANGE,
            )
            if int(config_dict.get("WriteNewFlowsToCsv", 0)) == 1:
                filename = "/database/ipfix_newflows.csv" if source == "ipfix" else "/database/newflows.csv"
                write_new_flow_to_csv(record, filename)
            records.append(record)
            total_packets += record["packets"]
            total_bytes += record["bytes"]
            for direction in ("src", "dst"):
                stats = ip_stats.setdefault(
                    record[f"{direction}_ip"],
                    {"src_packets": 0, "dst_packets": 0, "src_bytes": 0, "dst_bytes": 0},
                )
                stats[f"{direction}_packets"] += record["packets"]
                stats[f"{direction}_bytes"] += record["bytes"]

    update_new_flows(records)
    if not update_flow_metrics(total_packets, len(records), total_bytes, source=source):
        log_error(logger, f"[ERROR] Failed to update {name} metrics")
    for ip, stats in ip_stats.items():
        address = ipaddress.ip_address(ip)
        if any(address in network for network in local_networks):
            update_localhost_stats(
                ip, stats["src_packets"], stats["dst_packets"],
                stats["src_bytes"], stats["dst_bytes"],
            )
    if datagram_count:
        log_info(logger, f"[INFO] Processed {len(records)} {name} flows from {datagram_count} packets")


def drain_flow_packets(packet_queue):
    while True:
        try:
            yield packet_queue.get_nowait()
        except Empty:
            return


def process_flow_packets(packet_queue, parse_packet, name, source, stop_event):
    logger = logging.getLogger(__name__)
    while not stop_event.is_set():
        try:
            config_dict = get_config_settings()
            if not config_dict:
                log_error(logger, f"[ERROR] Failed to load configuration for {name}")
                stop_event.wait(60)
                continue
            interval = int(config_dict.get("CollectorProcessingInterval", 60))
            if interval <= 0:
                raise ValueError("CollectorProcessingInterval must be positive")
            ignorelist = get_ignorelist()
            packets = drain_flow_packets(packet_queue)
            process_flow_batch(packets, parse_packet, name, source, config_dict, ignorelist)
            stop_event.wait(interval)
        except (sqlite3.Error, ValueError, TypeError, OSError) as exc:
            log_error(logger, f"[ERROR] Failed to process {name} packets: {exc}")
            stop_event.wait(60)


def run_flow_collector(listen_address, listen_port, parse_packet, name, source,
                       packet_queue=None, stop_event=None):
    logger = logging.getLogger(__name__)
    packet_queue = packet_queue if packet_queue is not None else Queue()
    stop_event = stop_event if stop_event is not None else threading.Event()
    receiver_failed = threading.Event()
    family = socket.AF_INET6 if ":" in listen_address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as listener:
        try:
            listener.bind((listen_address, int(listen_port)))
        except (OSError, ValueError, OverflowError) as exc:
            log_error(logger, f"[ERROR] Cannot bind {name} listener: {exc}")
            raise
        listener.settimeout(1)
        log_info(logger, f"[INFO] {name} collector listening on {listen_address}:{listen_port}")
        receiver = threading.Thread(
            target=collect_flow_packets,
            args=(listener, packet_queue, stop_event, name, receiver_failed),
            daemon=True,
        )
        receiver.start()
        try:
            process_flow_packets(packet_queue, parse_packet, name, source, stop_event)
            if receiver_failed.is_set():
                raise OSError(f"{name} receiver failed")
        finally:
            stop_event.set()
            receiver.join(timeout=2)


def write_new_flow_to_csv(record, filename="/database/newflows.csv"):
    fieldnames = [
        "local_timestamp", "src_ip", "dst_ip", "nexthop", "input_iface",
        "output_iface", "packets", "bytes", "start_time", "end_time",
        "src_port", "dst_port", "tcp_flags", "protocol", "tos", "src_as",
        "dst_as", "src_mask", "dst_mask", "tags", "last_seen", "times_seen",
    ]
    try:
        line = ",".join(
            [datetime.now().isoformat()]
            + [str(record.get(key, "")) for key in fieldnames[1:]]
        ) + "\n"
        if not os.path.isfile(filename) or os.path.getsize(filename) == 0:
            with open(filename, "a") as handle:
                handle.write(",".join(fieldnames) + "\n")
        with open(filename, "a") as handle:
            handle.write(line)
    except OSError as exc:
        log_error(logging.getLogger(__name__), f"[ERROR] Failed to write flow to CSV: {exc}")
