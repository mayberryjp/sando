import bisect
import logging
import sqlite3

from src.const import CONST_EXPLORE_DB
from src.database.core import connect_to_db, delete_all_records, disconnect_from_db
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
        master_rows = []
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
            concat_values = [
                str(flow_id),
                str(src_ip),
                str(dst_ip),
                str(src_ip_int),
                str(dst_ip_int),
                str(src_port),
                str(dst_port),
                str(protocol),
                str(tags),
                str(flow_start),
                str(last_seen),
                str(packets),
                str(bytes_),
                str(times_seen),
                str(src_dns),
                str(dst_dns),
                str(src_country),
                str(dst_country),
                str(src_asn),
                str(dst_asn),
                str(src_isp),
                str(dst_isp),
                str(src_sandoname),
                str(dst_sandoname),
            ]
            concat = "_".join(concat_values)
            master_rows.append(
                (
                    flow_id,
                    src_ip,
                    dst_ip,
                    src_ip_int,
                    dst_ip_int,
                    src_port,
                    dst_port,
                    protocol,
                    tags,
                    flow_start,
                    last_seen,
                    packets,
                    bytes_,
                    times_seen,
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

        delete_all_records("explore")
        log_info(
            logger,
            f"[INFO] Inserting {len(master_rows)} rows into master_flow_view in {CONST_EXPLORE_DB}...",
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
                INSERT OR REPLACE INTO explore (
                    flow_id, src_ip, dst_ip, src_ip_int, dst_ip_int, src_port, dst_port, protocol, tags, flow_start, last_seen,
                    packets, bytes, times_seen,
                    src_dns, dst_dns, src_country, dst_country, src_asn, dst_asn, src_isp, dst_isp, src_sandoname, dst_sandoname, concat
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                batch,
            )
            tgt_conn.commit()
            # log_info(logger, f"[PROGRESS] Inserted {min(i+batch_size, total)}/{total} rows into master_flow_view...")

        disconnect_from_db(tgt_conn)
        log_info(
            logger,
            f"[INFO] Inserted {total} records into master_flow_view in {CONST_EXPLORE_DB}.",
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
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get total count of grouped results
        total_query = '''
            SELECT COUNT(*) FROM (
                SELECT 1 FROM explore
                WHERE src_port > dst_port
                GROUP BY
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
                    dst_sandoname
            )
        '''
        cursor.execute(total_query)
        total = cursor.fetchone()[0]

        query = """
                SELECT
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
                    SUM(packets)    AS sum_packets,
                    SUM(bytes)      AS sum_bytes,
                    SUM(times_seen) AS sum_times_seen,
                    MAX(last_seen)  AS max_last_seen,
                    COUNT(*)        AS row_count
                FROM explore
                WHERE src_port > dst_port
                GROUP BY
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
                    dst_sandoname
                ORDER BY sum_packets DESC
                LIMIT ? OFFSET ?
                """

        # Get paginated results
        cursor.execute(
            query,
            (limit, offset),
        )
        rows = cursor.fetchall()
        disconnect_from_db(conn)
        results = [dict(row) for row in rows]

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
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
        SELECT
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
            SUM(packets)    AS sum_packets,
            SUM(bytes)      AS sum_bytes,
            SUM(times_seen) AS sum_times_seen,
            MAX(last_seen)  AS max_last_seen,
            COUNT(*)        AS row_count
        FROM explore
        WHERE concat LIKE ? COLLATE NOCASE AND
        src_port > dst_port
        GROUP BY
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
            dst_sandoname
        ORDER BY sum_packets DESC
        LIMIT ? OFFSET ?
        """
        # Get total count of grouped results
        like_pattern = f"%{search_string}%"
        count_query = '''
            SELECT COUNT(*) FROM (
                SELECT 1 FROM explore
                WHERE concat LIKE ? COLLATE NOCASE AND src_port > dst_port
                GROUP BY
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
                    dst_sandoname
            )
        '''
        cursor.execute(count_query, (like_pattern,))
        total = cursor.fetchone()[0]

        # Get paginated results
        # query = """
        #     SELECT * FROM explore
        #     WHERE concat LIKE ? COLLATE NOCASE
        #     ORDER BY packets DESC
        #     LIMIT ? OFFSET ?
        # """
        cursor.execute(query, (like_pattern, page_size, offset))
        rows = cursor.fetchall()
        disconnect_from_db(conn)
        results = [dict(row) for row in rows]

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
