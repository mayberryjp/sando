import os
import sys
from pathlib import Path
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *
import socket
import struct
import sqlite3
import logging
from locallogging import log_info, log_error
import bisect

def ip_to_int(ip):
    """Convert dotted IP string to integer."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return None

def create_master_flow_view_table(db_path):
    """
    Create the master_flow_view table in the target database if it doesn't exist.
    Adds a 'concat' column for concatenated values.
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS master_flow_view (
                flow_id INTEGER PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                src_ip_int INTEGER,
                dst_ip_int INTEGER,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                tags TEXT,
                flow_start TEXT,
                last_seen TEXT,
                packets INTEGER,
                bytes INTEGER,
                times_seen INTEGER,
                dns_query TEXT,
                dns_response TEXT,
                src_country TEXT,
                dst_country TEXT,
                src_asn TEXT,
                dst_asn TEXT,
                src_isp TEXT,
                dst_isp TEXT,
                concat TEXT
            )
        """)
        conn.commit()
        conn.close()
        log_info(logging.getLogger(__name__), f"[INFO] master_flow_view table ensured in {db_path}")
    except Exception as e:
        log_error(logging.getLogger(__name__), f"[ERROR] Failed to create master_flow_view table in {db_path}: {e}")

def bulk_populate_master_flow_view(source_db_path, target_db_path):
    """
    Extract all data from allflows, dnskeyvalue, geolocation, and ipasn,
    join in Python memory, and bulk insert into master_flow_view in target_db_path.
    The 'concat' column is the '_' concatenation of all other columns for each row.
    """
    logger = logging.getLogger(__name__)
    try:
        log_info(logger, f"[INFO] Loading allflows from {source_db_path}...")
        src_conn = sqlite3.connect(source_db_path)
        src_conn.create_function("ip_to_int", 1, ip_to_int)
        src_cursor = src_conn.cursor()
        src_cursor.execute("SELECT rowid, src_ip, dst_ip, src_port, dst_port, protocol, tags, flow_start, last_seen, packets, bytes, times_seen FROM allflows")
        allflows_rows = src_cursor.fetchall()
        src_conn.close()
        log_info(logger, f"[INFO] Loaded {len(allflows_rows)} flows.")

        log_info(logger, f"[INFO] Loading dnskeyvalue from {target_db_path}...")
        tgt_conn = sqlite3.connect(target_db_path)
        tgt_cursor = tgt_conn.cursor()
        tgt_cursor.execute("SELECT ip, domain FROM dnskeyvalue")
        dnskeyvalue = dict(tgt_cursor.fetchall())

        log_info(logger, f"[INFO] Loading geolocation from {source_db_path}...")
        src_conn = sqlite3.connect(source_db_path)
        src_cursor = src_conn.cursor()
        src_cursor.execute("SELECT start_ip, end_ip, country_name FROM geolocation")
        geolocation_rows = src_cursor.fetchall()
        geolocations = []
        for start_ip, end_ip, country in geolocation_rows:
            geolocations.append((int(start_ip), int(end_ip), country))
        src_conn.close()

        log_info(logger, f"[INFO] Loading ipasn from {source_db_path}...")
        src_conn = sqlite3.connect(source_db_path)
        src_cursor = src_conn.cursor()
        src_cursor.execute("SELECT start_ip, end_ip, asn, isp_name FROM ipasn")
        ipasn_rows = src_cursor.fetchall()
        ipasns = []
        for start_ip, end_ip, asn, isp in ipasn_rows:
            ipasns.append((int(start_ip), int(end_ip), asn, isp))
        src_conn.close()

        # Prepare sorted lists for geolocation and ipasn
        geolocations_sorted = sorted(geolocations, key=lambda x: x[0])
        geo_starts = [start for start, end, country in geolocations_sorted]

        ipasns_sorted = sorted(ipasns, key=lambda x: x[0])
        ipasn_starts = [start for start, end, asn, isp in ipasns_sorted]

        def lookup_geo(ip_int):
            idx = bisect.bisect_right(geo_starts, ip_int) - 1
            if idx >= 0:
                start, end, country = geolocations_sorted[idx]
                if start <= ip_int <= end:
                    return country
            return None

        def lookup_ipasn(ip_int):
            idx = bisect.bisect_right(ipasn_starts, ip_int) - 1
            if idx >= 0:
                start, end, asn, isp = ipasns_sorted[idx]
                if start <= ip_int <= end:
                    return asn, isp
            return None, None

        log_info(logger, "[INFO] Joining data in memory and preparing for insert...")
        master_rows = []
        total_flows = len(allflows_rows)
        progress_step = max(1, total_flows // 50)  # Log progress every 2%
        for idx, row in enumerate(allflows_rows, 1):
            (flow_id, src_ip, dst_ip, src_port, dst_port, protocol, tags, flow_start, last_seen, packets, bytes_, times_seen) = row
            src_ip_int = ip_to_int(src_ip)
            dst_ip_int = ip_to_int(dst_ip)
            dns_query = dnskeyvalue.get(src_ip) or dnskeyvalue.get(dst_ip) or ''
            dns_response = ''
            src_country = lookup_geo(src_ip_int) if src_ip_int is not None else None
            dst_country = lookup_geo(dst_ip_int) if dst_ip_int is not None else None
            src_asn, src_isp = lookup_ipasn(src_ip_int) if src_ip_int is not None else (None, None)
            dst_asn, dst_isp = lookup_ipasn(dst_ip_int) if dst_ip_int is not None else (None, None)
            concat_values = [
                str(flow_id), str(src_ip), str(dst_ip), str(src_ip_int), str(dst_ip_int),
                str(src_port), str(dst_port), str(protocol), str(tags), str(flow_start), str(last_seen),
                str(packets), str(bytes_), str(times_seen),
                str(dns_query), str(dns_response), str(src_country), str(dst_country),
                str(src_asn), str(dst_asn), str(src_isp), str(dst_isp)
            ]
            concat = "_".join(concat_values)
            master_rows.append((
                flow_id, src_ip, dst_ip, src_ip_int, dst_ip_int, src_port, dst_port, protocol, tags, flow_start, last_seen,
                packets, bytes_, times_seen,
                dns_query, dns_response, src_country, dst_country, src_asn, dst_asn, src_isp, dst_isp, concat
            ))
            if idx % progress_step == 0 or idx == total_flows:
                log_info(logger, f"[PROGRESS] Joined {idx}/{total_flows} flows in memory...")

        log_info(logger, f"[INFO] Inserting {len(master_rows)} rows into master_flow_view in {target_db_path}...")

        # Batch insert with progress counter
        batch_size = 1000
        total = len(master_rows)
        for i in range(0, total, batch_size):
            batch = master_rows[i:i+batch_size]
            tgt_cursor.executemany("""
                INSERT OR REPLACE INTO master_flow_view (
                    flow_id, src_ip, dst_ip, src_ip_int, dst_ip_int, src_port, dst_port, protocol, tags, flow_start, last_seen,
                    packets, bytes, times_seen,
                    dns_query, dns_response, src_country, dst_country, src_asn, dst_asn, src_isp, dst_isp, concat
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, batch)
            tgt_conn.commit()
            log_info(logger, f"[PROGRESS] Inserted {min(i+batch_size, total)}/{total} rows into master_flow_view...")

        tgt_conn.close()
        log_info(logger, f"[INFO] Inserted {total} records into master_flow_view in {target_db_path}.")
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to bulk populate master_flow_view: {e}")

def refresh_master_flow_view(source_db_path, target_db_path):
    """
    Utility function to (re)create and populate the master_flow_view table in the target DB.
    """
    log_info(logging.getLogger(__name__), f"[INFO] Refreshing master_flow_view from {source_db_path} to {target_db_path}")
    create_master_flow_view_table(target_db_path)
    bulk_populate_master_flow_view(source_db_path, target_db_path)

def create_dns_key_value(target_db_path):
    """
    Runs get_ip_to_domain_mapping from database.dnsqueries and writes the results to exploreflow.db as dnskeyvalue table.
    """
    try:
        from database.dnsqueries import get_ip_to_domain_mapping
    except ImportError as e:
        log_error(logging.getLogger(__name__), f"[ERROR] Could not import get_ip_to_domain_mapping: {e}")
        return

    logger = logging.getLogger(__name__)
    try:
        log_info(logger, "[INFO] Running get_ip_to_domain_mapping...")
        mapping = get_ip_to_domain_mapping()
        if not mapping:
            log_info(logger, "[INFO] No DNS key-value data to write.")
            return

        log_info(logger, f"[INFO] Connecting to target database: {target_db_path}")
        conn = sqlite3.connect(target_db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dnskeyvalue (
                ip TEXT PRIMARY KEY,
                domain TEXT
            )
        """)
        # Prepare data for insertion
        rows = [(ip, domain) for ip, domain in mapping.items()]
        cursor.executemany(
            "INSERT OR REPLACE INTO dnskeyvalue (ip, domain) VALUES (?, ?)",
            rows
        )
        conn.commit()
        conn.close()
        log_info(logger, f"[INFO] Inserted {len(rows)} DNS key-value records into dnskeyvalue in {target_db_path}.")
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to create dnskeyvalue table: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Refresh the master_flow_view table with joined flow data.")
    parser.add_argument(
        "--source", 
        type=str, 
        default="/database/consolidated.db", 
        help="Path to the source consolidated database (default: /database/consolidated.db)"
    )
    parser.add_argument(
        "--target", 
        type=str, 
        default="/database/exploreflow.db", 
        help="Path to the target exploreflow database (default: /database/exploreflow.db)"
    )
    args = parser.parse_args()

    try:
        create_dns_key_value(args.target)
        print(f"dnskeyvalue table refreshed in {args.target}")
        refresh_master_flow_view(args.source, args.target)
        print(f"master_flow_view refreshed in {args.target}")

    except Exception as e:
        log_error(logging.getLogger(__name__), f"[ERROR] Exception in main: {e}")
        print(f"Error: {e}")

def get_latest_master_flows(limit=100, page=0):
    """
    Get `limit` rows from master_flow_view in CONST_EXPLORE_DB,
    sorted by last_seen descending, with pagination support.
    Returns a list of dictionaries (JSON serializable).
    """
    offset = page * limit
    conn = sqlite3.connect(CONST_EXPLORE_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM master_flow_view ORDER BY packets DESC LIMIT ? OFFSET ?",
        (limit, offset)
    )
    rows = cursor.fetchall()
    conn.close()
    # Convert sqlite3.Row objects to dictionaries
    result = [dict(row) for row in rows]
    return result

def search_master_flows_by_concat(search_string, page=0, page_size=100):
    """
    Search the master_flow_view table for rows where the concat column matches the search_string (wildcard, case-insensitive).
    Supports pagination via page and page_size.
    Returns a list of dictionaries.
    """
    offset = page * page_size
    conn = sqlite3.connect(CONST_EXPLORE_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Use LIKE for wildcard search, % for any substring match, and COLLATE NOCASE for case-insensitive
    query = """
        SELECT * FROM master_flow_view
        WHERE concat LIKE ? COLLATE NOCASE
        ORDER BY packets DESC
        LIMIT ? OFFSET ?
    """
    like_pattern = f"%{search_string}%"
    cursor.execute(query, (like_pattern, page_size, offset))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]