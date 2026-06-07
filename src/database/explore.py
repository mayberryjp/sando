import bisect
import logging

from src.const import CONST_CREATE_EXPLORE_SQL, CONST_EXPLORE_DB
from src.database.core import (
    connect_to_db,
    create_table,
    delete_all_records,
    disconnect_from_db,
)
from src.database.dnsqueries import get_ip_to_domain_mapping
from src.utils.locallogging import log_error, log_info
from src.utils.network import ip_to_int


def bulk_populate_master_flow_view():
    """
    Extract all data from allflows, dnskeyvalue, geolocation, and ipasn,
    join in Python memory, and bulk insert into master_flow_view in CONST_EXPLORE_DB.
    The 'concat' column is the '_' concatenation of all other columns for each row.
    """
    logger = logging.getLogger(__name__)
    try:
        log_info(logger, "[INFO] Loading allflows...")
        src_conn = connect_to_db("allflows")
        src_cursor = src_conn.cursor()
        src_cursor.execute(
            "SELECT rowid, src_ip, dst_ip, src_port, dst_port, protocol, tags, flow_start, last_seen, packets, bytes, times_seen FROM allflows"
        )
        allflows_rows = src_cursor.fetchall()
        disconnect_from_db(src_conn)
        log_info(logger, f"[INFO] Loaded {len(allflows_rows)} flows.")

        log_info(logger, "[INFO] Loading dnskeyvalue...")
        tgt_conn = connect_to_db("dnskeyvalue")
        tgt_cursor = tgt_conn.cursor()
        tgt_cursor.execute("SELECT ip, domain FROM dnskeyvalue")
        dnskeyvalue = dict(tgt_cursor.fetchall())
        disconnect_from_db(tgt_conn)

        log_info(logger, "[INFO] Loading geolocation...")
        src_conn = connect_to_db("geolocation")
        src_cursor = src_conn.cursor()
        src_cursor.execute("SELECT start_ip, end_ip, country_name FROM geolocation")
        geolocation_rows = src_cursor.fetchall()
        geolocations = []
        for start_ip, end_ip, country in geolocation_rows:
            geolocations.append((int(start_ip), int(end_ip), country))
        disconnect_from_db(src_conn)

        # Prepare sorted lists for geolocation and ipasn
        geolocations_sorted = sorted(geolocations, key=lambda x: x[0])
        geo_starts = [start for start, end, country in geolocations_sorted]

        log_info(logger, "[INFO] Loading ipasn...")
        src_conn = connect_to_db("ipasn")
        src_cursor = src_conn.cursor()
        src_cursor.execute("SELECT start_ip, end_ip, asn, isp_name FROM ipasn")
        ipasn_rows = src_cursor.fetchall()
        ipasns = []
        for start_ip, end_ip, asn, isp in ipasn_rows:
            ipasns.append((int(start_ip), int(end_ip), asn, isp))
        disconnect_from_db(src_conn)

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
        aggregated = {}
        # Load localhosts DNS hostnames
        tgt_conn = connect_to_db("localhosts")
        tgt_cursor = tgt_conn.cursor()
        tgt_cursor.execute(
            "SELECT ip_address, local_description, dns_hostname FROM localhosts"
        )
        localhosts = {
            ip: {
                "description": desc or "",
                "dns": dns or "",
            }
            for ip, desc, dns in tgt_cursor.fetchall()
        }
        disconnect_from_db(tgt_conn)

        for idx, row in enumerate(allflows_rows, 1):
            (
                flow_id,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                tags,
                flow_start,
                last_seen,
                packets,
                bytes_,
                times_seen,
            ) = row

            # Skip rows where src_port <= dst_port (pre-filter)
            if src_port <= dst_port:
                continue

            src_ip_int = ip_to_int(src_ip)
            dst_ip_int = ip_to_int(dst_ip)
            src_dns = dnskeyvalue.get(src_ip) or localhosts.get(src_ip, {}).get(
                "dns", ""
            )
            dst_dns = dnskeyvalue.get(dst_ip) or localhosts.get(dst_ip, {}).get(
                "dns", ""
            )
            src_country = lookup_geo(src_ip_int) if src_ip_int is not None else None
            dst_country = lookup_geo(dst_ip_int) if dst_ip_int is not None else None
            src_asn, src_isp = (
                lookup_ipasn(src_ip_int) if src_ip_int is not None else (None, None)
            )
            dst_asn, dst_isp = (
                lookup_ipasn(dst_ip_int) if dst_ip_int is not None else (None, None)
            )
            src_sandoname = localhosts.get(src_ip, {}).get("description", "")
            dst_sandoname = localhosts.get(dst_ip, {}).get("description", "")

            # Aggregate by group key
            group_key = (
                src_ip,
                dst_ip,
                src_ip_int,
                dst_ip_int,
                dst_port,
                protocol,
                tags,
                src_dns,
                dst_dns,
                src_country,
                dst_country,
                src_asn,
                dst_asn,
                src_isp,
                dst_isp,
                src_sandoname,
                dst_sandoname,
            )
            if group_key in aggregated:
                agg = aggregated[group_key]
                agg[0] += packets
                agg[1] += bytes_
                agg[2] += times_seen
                agg[3] += 1
                if last_seen and (agg[4] is None or last_seen > agg[4]):
                    agg[4] = last_seen
            else:
                aggregated[group_key] = [packets, bytes_, times_seen, 1, last_seen]

        # Build final rows with concat
        log_info(
            logger,
            f"[INFO] Aggregated {len(allflows_rows)} raw flows into {len(aggregated)} summary rows.",
        )
        master_rows = []
        for group_key, agg in aggregated.items():
            (
                src_ip,
                dst_ip,
                src_ip_int,
                dst_ip_int,
                dst_port,
                protocol,
                tags,
                src_dns,
                dst_dns,
                src_country,
                dst_country,
                src_asn,
                dst_asn,
                src_isp,
                dst_isp,
                src_sandoname,
                dst_sandoname,
            ) = group_key
            sum_packets, sum_bytes, sum_times_seen, row_count, max_last_seen = agg
            concat_values = [str(v) for v in group_key] + [
                str(sum_packets),
                str(sum_bytes),
                str(sum_times_seen),
                str(max_last_seen),
            ]
            concat = "_".join(concat_values)
            master_rows.append(
                (
                    src_ip,
                    dst_ip,
                    src_ip_int,
                    dst_ip_int,
                    dst_port,
                    protocol,
                    tags,
                    max_last_seen,
                    sum_packets,
                    sum_bytes,
                    sum_times_seen,
                    row_count,
                    src_dns,
                    dst_dns,
                    src_country,
                    dst_country,
                    src_asn,
                    dst_asn,
                    src_isp,
                    dst_isp,
                    src_sandoname,
                    dst_sandoname,
                    concat,
                )
            )
        # if idx % progress_step == 0 or idx == total_flows:
        # log_info(logger, f"[PROGRESS] Joined {idx}/{total_flows} flows in memory...")

        # Drop and recreate explore table to ensure schema is up to date
        tgt_conn = connect_to_db("explore")
        tgt_conn.execute("DROP TABLE IF EXISTS explore")
        disconnect_from_db(tgt_conn)
        create_table(CONST_CREATE_EXPLORE_SQL, "explore")

        log_info(
            logger,
            f"[INFO] Inserting {len(master_rows)} summary rows into explore in {CONST_EXPLORE_DB}...",
        )

        # Batch insert with progress counter
        batch_size = 1000
        total = len(master_rows)

        tgt_conn = connect_to_db("explore")
        tgt_cursor = tgt_conn.cursor()

        for i in range(0, total, batch_size):
            batch = master_rows[i : i + batch_size]
            tgt_cursor.executemany(
                """
                INSERT INTO explore (
                    src_ip, dst_ip, src_ip_int, dst_ip_int, dst_port, protocol, tags,
                    max_last_seen, sum_packets, sum_bytes, sum_times_seen, row_count,
                    src_dns, dst_dns, src_country, dst_country,
                    src_asn, dst_asn, src_isp, dst_isp,
                    src_sandoname, dst_sandoname, concat
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                batch,
            )
            tgt_conn.commit()

        disconnect_from_db(tgt_conn)
        log_info(
            logger,
            f"[INFO] Inserted {total} summary records into explore in {CONST_EXPLORE_DB}.",
        )
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to bulk populate master_flow_view: {e}")


def create_dns_key_value():
    """
    Runs get_ip_to_domain_mapping from src.database.dnsqueries and writes the results to exploreflow.db as dnskeyvalue table.
    """

    logger = logging.getLogger(__name__)
    try:
        log_info(logger, "[INFO] Running get_ip_to_domain_mapping...")
        mapping = get_ip_to_domain_mapping()
        if not mapping:
            log_info(logger, "[INFO] No DNS key-value data to write.")
            return

        log_info(logger, f"[INFO] Connecting to target database: {CONST_EXPLORE_DB}")
        delete_all_records("dnskeyvalue")
        conn = connect_to_db("dnskeyvalue")
        cursor = conn.cursor()
        # Prepare data for insertion
        rows = [(ip, domain) for ip, domain in mapping.items()]
        cursor.executemany(
            "INSERT OR REPLACE INTO dnskeyvalue (ip, domain) VALUES (?, ?)", rows
        )
        conn.commit()
        disconnect_from_db(conn)
        log_info(
            logger,
            f"[INFO] Inserted {len(rows)} DNS key-value records into dnskeyvalue in {CONST_EXPLORE_DB}.",
        )
    except Exception as e:
        log_error(logger, f"[ERROR] Failed to create dnskeyvalue table: {e}")


def get_latest_master_flows(limit=100, page=0):
    """
    Get `limit` rows from explore in CONST_EXPLORE_DB,
    sorted by packets descending, with pagination support.
    Returns a dict with 'total', 'page', 'limit', and 'results'.
    """
    try:
        offset = page * limit
        conn = connect_to_db("explore")
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM explore")
        total = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT
                src_ip, dst_ip, src_ip_int, dst_ip_int, dst_port, protocol, tags,
                src_dns, dst_dns, src_country, dst_country,
                src_asn, dst_asn, src_isp, dst_isp,
                src_sandoname, dst_sandoname,
                sum_packets, sum_bytes, sum_times_seen, max_last_seen, row_count
            FROM explore
            ORDER BY sum_packets DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        disconnect_from_db(conn)
        results = [dict(zip(columns, row)) for row in rows]

        return {
            "total": total,
            "page": page,
            "limit": limit,
            "results": results,
            "success": True,
        }
    except Exception as e:
        log_error(
            logging.getLogger(__name__),
            f"[ERROR] Failed to get latest master flows: {e}",
        )
        return {
            "total": 0,
            "page": page,
            "limit": limit,
            "results": [],
            "success": False,
            "error": str(e),
        }


def search_master_flows_by_concat(search_string, page=0, page_size=100):
    """
    Search the explore table for rows where the concat column matches the search_string (wildcard, case-insensitive).
    Supports pagination via page and page_size.
    Returns a dict with 'total', 'page', 'page_size', and 'results'.
    """
    try:
        offset = page * page_size
        conn = connect_to_db("explore")
        cursor = conn.cursor()

        like_pattern = f"%{search_string}%"

        cursor.execute(
            "SELECT COUNT(*) FROM explore WHERE concat LIKE ? COLLATE NOCASE",
            (like_pattern,),
        )
        total = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT
                src_ip, dst_ip, src_ip_int, dst_ip_int, dst_port, protocol, tags,
                src_dns, dst_dns, src_country, dst_country,
                src_asn, dst_asn, src_isp, dst_isp,
                src_sandoname, dst_sandoname,
                sum_packets, sum_bytes, sum_times_seen, max_last_seen, row_count
            FROM explore
            WHERE concat LIKE ? COLLATE NOCASE
            ORDER BY sum_packets DESC
            LIMIT ? OFFSET ?
            """,
            (like_pattern, page_size, offset),
        )
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        disconnect_from_db(conn)
        results = [dict(zip(columns, row)) for row in rows]

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "results": results,
            "success": True,
        }
    except Exception as e:
        log_error(
            logging.getLogger(__name__),
            f"[ERROR] Failed to search master flows by concat: {e}",
        )
        return {
            "total": 0,
            "page": page,
            "page_size": page_size,
            "results": [],
            "success": False,
            "error": str(e),
        }


_FLOW_COLUMNS = """
    src_ip, dst_ip, dst_port, protocol, sum_packets, sum_bytes,
    sum_times_seen, max_last_seen, tags,
    src_dns, dst_dns, src_country, dst_country, src_asn, dst_asn,
    src_isp, dst_isp, src_sandoname, dst_sandoname
"""


def get_top_flows(limit=25, order_by="bytes"):
    """Return top flows across all hosts ordered by bytes or packets."""
    order_col = "sum_bytes" if order_by != "packets" else "sum_packets"
    try:
        conn = connect_to_db("explore")
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT {_FLOW_COLUMNS} FROM explore ORDER BY {order_col} DESC LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        disconnect_from_db(conn)
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        log_error(logging.getLogger(__name__), f"[ERROR] get_top_flows failed: {e}")
        return []


def get_flows_for_ip(ip_address, limit=25, order_by="bytes"):
    """Return flows where src_ip or dst_ip matches, ordered by bytes or packets."""
    order_col = "sum_bytes" if order_by != "packets" else "sum_packets"
    try:
        conn = connect_to_db("explore")
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT {_FLOW_COLUMNS} FROM explore WHERE src_ip = ? OR dst_ip = ? ORDER BY {order_col} DESC LIMIT ?",
            (ip_address, ip_address, limit),
        )
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        disconnect_from_db(conn)
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        log_error(logging.getLogger(__name__), f"[ERROR] get_flows_for_ip failed: {e}")
        return []


def get_flows_for_country(country, limit=50):
    """Return flows where src or dst country matches (partial, case-insensitive)."""
    try:
        conn = connect_to_db("explore")
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT {_FLOW_COLUMNS} FROM explore WHERE src_country LIKE ? OR dst_country LIKE ? ORDER BY sum_bytes DESC LIMIT ?",
            (f"%{country}%", f"%{country}%", limit),
        )
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        disconnect_from_db(conn)
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        log_error(
            logging.getLogger(__name__), f"[ERROR] get_flows_for_country failed: {e}"
        )
        return []


def get_flows_for_port(port, limit=50):
    """Return flows on a specific destination port."""
    try:
        conn = connect_to_db("explore")
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT {_FLOW_COLUMNS} FROM explore WHERE dst_port = ? ORDER BY sum_bytes DESC LIMIT ?",
            (port, limit),
        )
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        disconnect_from_db(conn)
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        log_error(
            logging.getLogger(__name__), f"[ERROR] get_flows_for_port failed: {e}"
        )
        return []


def get_flows_for_tag(tag, limit=50):
    """Return flows whose tags column contains the given tag string."""
    try:
        conn = connect_to_db("explore")
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT {_FLOW_COLUMNS} FROM explore WHERE tags LIKE ? ORDER BY sum_bytes DESC LIMIT ?",
            (f"%{tag}%", limit),
        )
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        disconnect_from_db(conn)
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        log_error(logging.getLogger(__name__), f"[ERROR] get_flows_for_tag failed: {e}")
        return []


def search_flows(
    src_ip=None, dst_ip=None, dst_port=None, country=None, tag=None, limit=50
):
    """Flexible flow search; all filters are optional and combined with AND logic."""
    clauses = []
    params = []
    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if dst_ip:
        clauses.append("dst_ip = ?")
        params.append(dst_ip)
    if dst_port is not None:
        clauses.append("dst_port = ?")
        params.append(dst_port)
    if country:
        clauses.append("(src_country LIKE ? OR dst_country LIKE ?)")
        params.extend([f"%{country}%", f"%{country}%"])
    if tag:
        clauses.append("tags LIKE ?")
        params.append(f"%{tag}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    try:
        conn = connect_to_db("explore")
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT {_FLOW_COLUMNS} FROM explore {where} ORDER BY sum_bytes DESC LIMIT ?",
            params,
        )
        rows = cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        disconnect_from_db(conn)
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        log_error(logging.getLogger(__name__), f"[ERROR] search_flows failed: {e}")
        return []
