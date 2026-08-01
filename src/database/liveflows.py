import logging

from src.database.core import connect_to_db, disconnect_from_db
from src.utils.locallogging import log_error

_FLOW_COLUMNS = (
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "src_packets",
    "src_bytes",
    "dst_packets",
    "dst_bytes",
    "flow_start",
    "last_seen",
    "tags",
)

# CTE query: aggregate all src_ports into one row per (src_ip, dst_ip, dst_port, protocol).
# forward = client→server (src_port > dst_port), reverse = server→client (src_port < dst_port).
def _flow_query(extra_where="", order="f.last_seen DESC"):
    return f"""
        WITH forward AS (
            SELECT src_ip, dst_ip, dst_port, protocol,
                   SUM(packets) AS src_packets, SUM(bytes) AS src_bytes,
                   MIN(flow_start) AS flow_start, MAX(last_seen) AS last_seen,
                   tags
            FROM newflows
            WHERE src_port > dst_port {extra_where}
            GROUP BY src_ip, dst_ip, dst_port, protocol
        ),
        reverse AS (
            SELECT dst_ip AS client_ip, src_ip AS server_ip, src_port AS service_port, protocol,
                   SUM(packets) AS dst_packets, SUM(bytes) AS dst_bytes
            FROM newflows
            WHERE src_port < dst_port {extra_where}
            GROUP BY dst_ip, src_ip, src_port, protocol
        )
        SELECT
            f.src_ip, f.dst_ip, f.dst_port, f.protocol,
            f.src_packets, f.src_bytes,
            COALESCE(r.dst_packets, 0) AS dst_packets,
            COALESCE(r.dst_bytes,   0) AS dst_bytes,
            f.flow_start, f.last_seen, f.tags
        FROM forward f
        LEFT JOIN reverse r ON (
            r.client_ip = f.src_ip AND r.server_ip = f.dst_ip
            AND r.service_port = f.dst_port AND r.protocol = f.protocol
        )
        ORDER BY {order}
    """


def _rows_to_dicts(rows):
    return [dict(zip(_FLOW_COLUMNS, row)) for row in rows]


def _load_host_lookups():
    """Return (localhosts_dict, dnskeyvalue_dict) for host name enrichment."""
    localhosts = {}
    dnskeyvalue = {}
    try:
        conn = connect_to_db("localhosts")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ip_address, local_description, dns_hostname FROM localhosts"
        )
        localhosts = {
            ip: {"description": desc or "", "dns": dns or ""}
            for ip, desc, dns in cursor.fetchall()
        }
        disconnect_from_db(conn)
    except Exception:
        pass
    try:
        conn = connect_to_db("dnskeyvalue")
        cursor = conn.cursor()
        cursor.execute("SELECT ip, domain FROM dnskeyvalue")
        dnskeyvalue = dict(cursor.fetchall())
        disconnect_from_db(conn)
    except Exception:
        pass
    return localhosts, dnskeyvalue


def _resolve_host(ip, localhosts, dnskeyvalue):
    """Return the best human-readable name for an IP, falling back to the IP itself."""
    local = localhosts.get(ip, {})
    return local.get("description") or local.get("dns") or dnskeyvalue.get(ip) or ip


def _enrich_flows(flows):
    """Add src_name and dst_name fields to each flow dict."""
    if not flows:
        return flows
    localhosts, dnskeyvalue = _load_host_lookups()
    for flow in flows:
        flow["src_name"] = _resolve_host(flow["src_ip"], localhosts, dnskeyvalue)
        flow["dst_name"] = _resolve_host(flow["dst_ip"], localhosts, dnskeyvalue)
    return flows


def get_live_snapshot(limit=200):
    """Return the most recent flows from newflows ordered by last_seen DESC."""
    logger = logging.getLogger(__name__)
    conn = None
    try:
        conn = connect_to_db("newflows")
        cursor = conn.cursor()
        cursor.execute(_flow_query() + " LIMIT ?", (limit,))
        return _enrich_flows(_rows_to_dicts(cursor.fetchall()))
    except Exception as e:
        log_error(logger, f"[ERROR] get_live_snapshot failed: {e}")
        return []
    finally:
        if conn:
            disconnect_from_db(conn)


def get_flows_since(seconds=60, limit=500):
    """Return newflows rows active in the last N seconds, oldest first."""
    logger = logging.getLogger(__name__)
    conn = None
    try:
        conn = connect_to_db("newflows")
        cursor = conn.cursor()
        time_filter = f"AND last_seen > datetime('now', 'localtime', '-{int(seconds)} seconds')"
        cursor.execute(
            _flow_query(extra_where=time_filter, order="f.last_seen ASC") + " LIMIT ?",
            (limit,),
        )
        return _enrich_flows(_rows_to_dicts(cursor.fetchall()))
    except Exception as e:
        log_error(logger, f"[ERROR] get_flows_since failed: {e}")
        return []
    finally:
        if conn:
            disconnect_from_db(conn)


def get_live_stats(window_seconds=60):
    """
    Return aggregate stats for flows active within the last window_seconds.

    Returns a dict with:
      - top_src_ips:   [{ip, bytes, packets, flow_count}]
      - top_dst_ips:   [{ip, bytes, packets, flow_count}]
      - top_dst_ports: [{port, protocol, bytes, flow_count}]
      - top_protocols: [{protocol, bytes, packets, flow_count}]
      - totals:        {flows, bytes, packets}
    """
    logger = logging.getLogger(__name__)
    conn = None
    try:
        conn = connect_to_db("allflows")
        cursor = conn.cursor()

        since = f"datetime('now', 'localtime', '-{window_seconds} seconds')"
        filt = f"WHERE last_seen > {since} AND src_port > dst_port"

        cursor.execute(
            f"SELECT src_ip, SUM(bytes), SUM(packets), COUNT(*) FROM allflows "
            f"{filt} GROUP BY src_ip ORDER BY SUM(bytes) DESC LIMIT 20"
        )
        top_src_ips = [
            {"ip": r[0], "bytes": r[1], "packets": r[2], "flow_count": r[3]}
            for r in cursor.fetchall()
        ]

        cursor.execute(
            f"SELECT dst_ip, SUM(bytes), SUM(packets), COUNT(*) FROM allflows "
            f"{filt} GROUP BY dst_ip ORDER BY SUM(bytes) DESC LIMIT 20"
        )
        top_dst_ips = [
            {"ip": r[0], "bytes": r[1], "packets": r[2], "flow_count": r[3]}
            for r in cursor.fetchall()
        ]

        cursor.execute(
            f"SELECT dst_port, protocol, SUM(bytes), COUNT(*) FROM allflows "
            f"{filt} GROUP BY dst_port, protocol ORDER BY SUM(bytes) DESC LIMIT 20"
        )
        top_dst_ports = [
            {"port": r[0], "protocol": r[1], "bytes": r[2], "flow_count": r[3]}
            for r in cursor.fetchall()
        ]

        cursor.execute(
            f"SELECT protocol, SUM(bytes), SUM(packets), COUNT(*) FROM allflows "
            f"{filt} GROUP BY protocol ORDER BY SUM(bytes) DESC"
        )
        top_protocols = [
            {"protocol": r[0], "bytes": r[1], "packets": r[2], "flow_count": r[3]}
            for r in cursor.fetchall()
        ]

        cursor.execute(
            f"SELECT COUNT(*), SUM(bytes), SUM(packets) FROM allflows {filt}"
        )
        row = cursor.fetchone()
        totals = {
            "flows": row[0] or 0,
            "bytes": row[1] or 0,
            "packets": row[2] or 0,
        }

        return {
            "top_src_ips": top_src_ips,
            "top_dst_ips": top_dst_ips,
            "top_dst_ports": top_dst_ports,
            "top_protocols": top_protocols,
            "totals": totals,
            "window_seconds": window_seconds,
        }
    except Exception as e:
        log_error(logger, f"[ERROR] get_live_stats failed: {e}")
        return {}
    finally:
        if conn:
            disconnect_from_db(conn)
