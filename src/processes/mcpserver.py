"""
Sando MCP Server using FastMCP and sqlite3 for database access.

Available tools:
  Host investigation:
    get_host                 - Full profile for a host (details + alerts + flow summary)
    get_host_alerts          - All alerts for a specific host
    get_host_flows           - Top flows originating from a host

  Flow explorer / investigation:
    get_top_flows            - Top flows across all hosts ordered by bytes or packets
    search_flows             - Flexible flow search (src_ip, dst_ip, port, country, tag)
    get_flows_by_country     - All flows to/from a specific country
    get_flows_by_port        - All flows on a specific destination port
    get_flows_by_tag         - All flows carrying a specific tag

  Allow / whitelist export:
    export_ignorelist        - Export all active ignore-list (allow-list) entries
    export_whitelisted_hosts - Export all hosts with the whitelisted flag set

  Configuration:
    list_configuration       - All configuration key/value pairs
    list_alerts              - All alerts (unfiltered)
"""

import os
import sys
import sqlite3
from typing import Optional
from fastmcp import FastMCP

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from const import (
    CONST_ALERTS_DB,
    CONST_ALLFLOWS_DB,
    CONST_CONFIGURATION_DB,
    CONST_EXPLORE_DB,
    CONST_IGNORELIST_DB,
    CONST_LOCALHOSTS_DB,
)


def _db(db_const: str) -> sqlite3.Connection:
    """Open a read-only-safe connection to a database, resolving container-style paths."""
    if os.path.isabs(db_const):
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        path = os.path.join(base, db_const.lstrip('/\\'))
    else:
        path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', db_const))
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


app = FastMCP("Sando MCP Server")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@app.tool("list_configuration")
def list_configuration():
    """Return all configuration key/value pairs."""
    conn = _db(CONST_CONFIGURATION_DB)
    rows = conn.execute("SELECT key, value, last_changed FROM configuration").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@app.tool("list_alerts")
def list_alerts(unacknowledged_only: bool = False):
    """
    Return all alerts.

    Args:
        unacknowledged_only: When True only return alerts where acknowledged = 0.
    """
    conn = _db(CONST_ALERTS_DB)
    if unacknowledged_only:
        rows = conn.execute("SELECT * FROM alerts WHERE acknowledged = 0 ORDER BY last_seen DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY last_seen DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.tool("get_host_alerts")
def get_host_alerts(ip_address: str):
    """
    Return all alerts for a specific host IP address, most recent first.

    Args:
        ip_address: The IPv4 or IPv6 address of the host to look up.
    """
    conn = _db(CONST_ALERTS_DB)
    rows = conn.execute(
        "SELECT * FROM alerts WHERE ip_address = ? ORDER BY last_seen DESC",
        (ip_address,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Host investigation
# ---------------------------------------------------------------------------

@app.tool("get_host")
def get_host(ip_address: str):
    """
    Return a full profile for a host including its database record,
    open alerts, and top-10 flows by bytes.

    Args:
        ip_address: The IPv4 address or MAC address of the host.
    """
    # Host record
    lconn = _db(CONST_LOCALHOSTS_DB)
    host_row = lconn.execute(
        """
        SELECT ip_address, mac_address, mac_vendor, dhcp_hostname, dns_hostname,
               os_fingerprint, local_description, icon, tags, threat_score,
               alerts_enabled, management_link, first_seen, last_seen,
               last_dhcp_discover, whitelisted, total_packets_src, total_packets_dst,
               total_bytes_src, total_bytes_dst, ip6_address
        FROM localhosts
        WHERE ip_address = ? OR mac_address = ?
        """,
        (ip_address, ip_address),
    ).fetchone()
    lconn.close()

    host = dict(host_row) if host_row else None

    # Alerts
    aconn = _db(CONST_ALERTS_DB)
    alert_rows = aconn.execute(
        "SELECT * FROM alerts WHERE ip_address = ? ORDER BY last_seen DESC",
        (ip_address,),
    ).fetchall()
    aconn.close()

    # Top flows from explore (enriched with country/ASN/DNS)
    econn = _db(CONST_EXPLORE_DB)
    flow_rows = econn.execute(
        """
        SELECT src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes,
               times_seen, flow_start, last_seen, tags,
               src_dns, dst_dns, src_country, dst_country, src_asn, dst_asn,
               src_isp, dst_isp, src_sandoname, dst_sandoname
        FROM explore
        WHERE src_ip = ? OR dst_ip = ?
        ORDER BY bytes DESC
        LIMIT 10
        """,
        (ip_address, ip_address),
    ).fetchall()
    econn.close()

    return {
        "host": host,
        "alerts": [dict(r) for r in alert_rows],
        "top_flows": [dict(r) for r in flow_rows],
    }


@app.tool("get_host_flows")
def get_host_flows(ip_address: str, limit: int = 25, order_by: str = "bytes"):
    """
    Return flows originating from or destined to a host, enriched with geo/ASN/DNS.

    Args:
        ip_address: Source or destination IP address to filter on.
        limit:      Maximum number of flows to return (default 25).
        order_by:   Sort column — "bytes" (default) or "packets".
    """
    order_col = "bytes" if order_by != "packets" else "packets"
    conn = _db(CONST_EXPLORE_DB)
    rows = conn.execute(
        f"""
        SELECT src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes,
               times_seen, flow_start, last_seen, tags,
               src_dns, dst_dns, src_country, dst_country,
               src_asn, dst_asn, src_isp, dst_isp,
               src_sandoname, dst_sandoname
        FROM explore
        WHERE src_ip = ? OR dst_ip = ?
        ORDER BY {order_col} DESC
        LIMIT ?
        """,
        (ip_address, ip_address, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Flow explorer / investigation
# ---------------------------------------------------------------------------

@app.tool("get_top_flows")
def get_top_flows(limit: int = 25, order_by: str = "bytes"):
    """
    Return the top flows across all hosts, enriched with geo/ASN/DNS.

    Args:
        limit:    Maximum number of flows to return (default 25).
        order_by: Sort column — "bytes" (default) or "packets".
    """
    order_col = "bytes" if order_by != "packets" else "packets"
    conn = _db(CONST_EXPLORE_DB)
    rows = conn.execute(
        f"""
        SELECT src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes,
               times_seen, flow_start, last_seen, tags,
               src_dns, dst_dns, src_country, dst_country,
               src_asn, dst_asn, src_isp, dst_isp,
               src_sandoname, dst_sandoname
        FROM explore
        ORDER BY {order_col} DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.tool("search_flows")
def search_flows(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    country: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = 50,
):
    """
    Flexible flow search against the enriched explore table.
    All filters are optional and combined with AND logic.

    Args:
        src_ip:   Filter by source IP address.
        dst_ip:   Filter by destination IP address.
        dst_port: Filter by destination port number.
        country:  Filter by source or destination country name (partial match).
        tag:      Filter flows whose tags column contains this string.
        limit:    Maximum rows to return (default 50).
    """
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

    conn = _db(CONST_EXPLORE_DB)
    rows = conn.execute(
        f"""
        SELECT src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes,
               times_seen, flow_start, last_seen, tags,
               src_dns, dst_dns, src_country, dst_country,
               src_asn, dst_asn, src_isp, dst_isp,
               src_sandoname, dst_sandoname
        FROM explore
        {where}
        ORDER BY bytes DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.tool("get_flows_by_country")
def get_flows_by_country(country: str, limit: int = 50):
    """
    Return flows where the source or destination country matches.

    Args:
        country: Country name or partial name to match (case-insensitive).
        limit:   Maximum rows to return (default 50).
    """
    conn = _db(CONST_EXPLORE_DB)
    rows = conn.execute(
        """
        SELECT src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes,
               times_seen, flow_start, last_seen, tags,
               src_dns, dst_dns, src_country, dst_country,
               src_asn, dst_asn, src_isp, dst_isp,
               src_sandoname, dst_sandoname
        FROM explore
        WHERE src_country LIKE ? OR dst_country LIKE ?
        ORDER BY bytes DESC
        LIMIT ?
        """,
        (f"%{country}%", f"%{country}%", limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.tool("get_flows_by_port")
def get_flows_by_port(port: int, limit: int = 50):
    """
    Return all flows on a specific destination port.

    Args:
        port:  Destination port number.
        limit: Maximum rows to return (default 50).
    """
    conn = _db(CONST_EXPLORE_DB)
    rows = conn.execute(
        """
        SELECT src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes,
               times_seen, flow_start, last_seen, tags,
               src_dns, dst_dns, src_country, dst_country,
               src_asn, dst_asn, src_isp, dst_isp,
               src_sandoname, dst_sandoname
        FROM explore
        WHERE dst_port = ?
        ORDER BY bytes DESC
        LIMIT ?
        """,
        (port, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.tool("get_flows_by_tag")
def get_flows_by_tag(tag: str, limit: int = 50):
    """
    Return all flows that carry a specific tag (e.g. "Geolocation", "Reputation", "TorNode").

    Args:
        tag:   Tag string to search for (partial match).
        limit: Maximum rows to return (default 50).
    """
    conn = _db(CONST_EXPLORE_DB)
    rows = conn.execute(
        """
        SELECT src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes,
               times_seen, flow_start, last_seen, tags,
               src_dns, dst_dns, src_country, dst_country,
               src_asn, dst_asn, src_isp, dst_isp,
               src_sandoname, dst_sandoname
        FROM explore
        WHERE tags LIKE ?
        ORDER BY bytes DESC
        LIMIT ?
        """,
        (f"%{tag}%", limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Allow list / whitelist export
# ---------------------------------------------------------------------------

@app.tool("export_ignorelist")
def export_ignorelist():
    """
    Export all active ignore-list (allow-list) entries.
    These are flows that are suppressed from alerting.
    """
    conn = _db(CONST_IGNORELIST_DB)
    rows = conn.execute(
        """
        SELECT ignorelist_id, ignorelist_src_ip, ignorelist_dst_ip,
               ignorelist_dst_port, ignorelist_protocol,
               ignorelist_description, ignorelist_added, ignorelist_insert_date
        FROM ignorelist
        WHERE ignorelist_enabled = 1
        ORDER BY ignorelist_insert_date DESC
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.tool("export_whitelisted_hosts")
def export_whitelisted_hosts():
    """
    Export all hosts that have the whitelisted flag set.
    These hosts are excluded from threat-detection processing.
    """
    conn = _db(CONST_LOCALHOSTS_DB)
    rows = conn.execute(
        """
        SELECT ip_address, mac_address, mac_vendor, dhcp_hostname, dns_hostname,
               local_description, icon, tags, threat_score, first_seen, last_seen,
               ip6_address
        FROM localhosts
        WHERE whitelisted = 1
        ORDER BY ip_address
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio
    asyncio.run(app.run_http_async(host="0.0.0.0", port=8044))

