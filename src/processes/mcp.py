import logging
import os
import sys
from typing import Optional

from database.alerts import get_all_alerts, get_all_alerts_by_ip  # noqa: E402
from database.configuration import get_all_configuration  # noqa: E402
from database.explore import (
    get_flows_for_country,
    get_flows_for_ip,
    get_flows_for_port,
    get_flows_for_tag,
)
from database.explore import get_top_flows as db_get_top_flows  # noqa: E402
from database.explore import search_flows as db_search_flows
from database.ignorelist import get_all_ignorelist_entries  # noqa: E402
from database.localhosts import get_localhost_as_dict  # noqa: E402
from database.localhosts import get_whitelisted_localhosts
from utils.locallogging import log_error, log_info  # noqa: E402

# Force unbuffered stdout so print() output appears immediately
os.environ["PYTHONUNBUFFERED"] = "1"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

# Suppress FastMCP's rich/colored logging and startup banner before anything else loads.
import fastmcp.settings as _fmcp_settings  # noqa: E402

_fmcp_settings.log_enabled = False  # prevent FastMCP from installing its own handlers
_fmcp_settings.enable_rich_logging = (
    False  # no RichHandler even if log_enabled were True
)

from fastmcp import FastMCP  # noqa: E402

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)  # sando/src/
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)  # sando/ — required by locallogging's "from src.X import"
# locallogging uses print() for all output, so the Python logging system only
# needs a NullHandler on the root logger.  Without this, every logger.info()
# call inside locallogging produces a second, unformatted duplicate line via
# the root StreamHandler.  Third-party loggers (mcp, uvicorn, fastmcp…) are
# also silenced here so their unformatted internal messages don't appear.
_root = logging.getLogger()
_root.handlers.clear()
_root.addHandler(logging.NullHandler())
_root.setLevel(logging.DEBUG)
for _name in (
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
    "fastmcp",
    "httpx",
    "mcp",
    "mcp.server",
    "mcp.server.session",
    "mcp.server.streamable_http_manager",
    "asyncio",
):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)


app = FastMCP("Sando MCP Server")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@app.tool("list_configuration")
def list_configuration():
    """Return all configuration key/value pairs."""
    try:
        log_info(logger, "[INFO] MCP list_configuration called")
        result = get_all_configuration()
        log_info(logger, f"[INFO] MCP list_configuration returned {len(result)} items")
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] list_configuration failed: {e}")
        return []


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
    try:
        log_info(
            logger,
            f"[INFO] MCP list_alerts called (unacknowledged_only={unacknowledged_only})",
        )
        alerts = get_all_alerts()
        if unacknowledged_only:
            alerts = [a for a in alerts if not a.get("acknowledged")]
        log_info(logger, f"[INFO] MCP list_alerts returned {len(alerts)} items")
        return alerts
    except Exception as e:
        log_error(logger, f"[ERROR] list_alerts failed: {e}")
        return []


@app.tool("get_host_alerts")
def get_host_alerts(ip_address: str):
    """
    Return all alerts for a specific host IP address, most recent first.

    Args:
        ip_address: The IPv4 or IPv6 address of the host to look up.
    """
    try:
        log_info(logger, f"[INFO] MCP get_host_alerts called for {ip_address}")
        result = get_all_alerts_by_ip(ip_address)
        log_info(
            logger,
            f"[INFO] MCP get_host_alerts returned {len(result)} items for {ip_address}",
        )
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] get_host_alerts failed for {ip_address}: {e}")
        return []


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
    try:
        log_info(logger, f"[INFO] MCP get_host called for {ip_address}")
        result = {
            "host": get_localhost_as_dict(ip_address),
            "alerts": get_all_alerts_by_ip(ip_address),
            "top_flows": get_flows_for_ip(ip_address, limit=10),
        }
        log_info(
            logger,
            f"[INFO] MCP get_host returned host={'found' if result.get('host') else 'not found'}, {len(result.get('alerts', []))} alerts, {len(result.get('top_flows', []))} flows for {ip_address}",
        )
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] get_host failed for {ip_address}: {e}")
        return {}


@app.tool("get_host_flows")
def get_host_flows(ip_address: str, limit: int = 25, order_by: str = "bytes"):
    """
    Return flows originating from or destined to a host, enriched with geo/ASN/DNS.

    Args:
        ip_address: Source or destination IP address to filter on.
        limit:      Maximum number of flows to return (default 25).
        order_by:   Sort column — "bytes" (default) or "packets".
    """
    try:
        log_info(
            logger,
            f"[INFO] MCP get_host_flows called for {ip_address} (limit={limit}, order_by={order_by})",
        )
        result = get_flows_for_ip(ip_address, limit=limit, order_by=order_by)
        log_info(
            logger,
            f"[INFO] MCP get_host_flows returned {len(result)} flows for {ip_address}",
        )
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] get_host_flows failed for {ip_address}: {e}")
        return []


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
    try:
        log_info(
            logger,
            f"[INFO] MCP get_top_flows called (limit={limit}, order_by={order_by})",
        )
        result = db_get_top_flows(limit=limit, order_by=order_by)
        log_info(logger, f"[INFO] MCP get_top_flows returned {len(result)} flows")
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] get_top_flows failed: {e}")
        return []


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
    try:
        log_info(
            logger,
            f"[INFO] MCP search_flows called (src_ip={src_ip}, dst_ip={dst_ip}, dst_port={dst_port}, country={country}, tag={tag}, limit={limit})",
        )
        result = db_search_flows(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            country=country,
            tag=tag,
            limit=limit,
        )
        log_info(logger, f"[INFO] MCP search_flows returned {len(result)} flows")
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] search_flows failed: {e}")
        return []


@app.tool("get_flows_by_country")
def get_flows_by_country(country: str, limit: int = 50):
    """
    Return flows where the source or destination country matches.

    Args:
        country: Country name or partial name to match (case-insensitive).
        limit:   Maximum rows to return (default 50).
    """
    try:
        log_info(
            logger,
            f"[INFO] MCP get_flows_by_country called for '{country}' (limit={limit})",
        )
        result = get_flows_for_country(country, limit=limit)
        log_info(
            logger,
            f"[INFO] MCP get_flows_by_country returned {len(result)} flows for '{country}'",
        )
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] get_flows_by_country failed for '{country}': {e}")
        return []


@app.tool("get_flows_by_port")
def get_flows_by_port(port: int, limit: int = 50):
    """
    Return all flows on a specific destination port.

    Args:
        port:  Destination port number.
        limit: Maximum rows to return (default 50).
    """
    try:
        log_info(
            logger,
            f"[INFO] MCP get_flows_by_port called for port {port} (limit={limit})",
        )
        result = get_flows_for_port(port, limit=limit)
        log_info(
            logger,
            f"[INFO] MCP get_flows_by_port returned {len(result)} flows for port {port}",
        )
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] get_flows_by_port failed for port {port}: {e}")
        return []


@app.tool("get_flows_by_tag")
def get_flows_by_tag(tag: str, limit: int = 50):
    """
    Return all flows that carry a specific tag (e.g. "Geolocation", "Reputation", "TorNode").

    Args:
        tag:   Tag string to search for (partial match).
        limit: Maximum rows to return (default 50).
    """
    try:
        log_info(
            logger,
            f"[INFO] MCP get_flows_by_tag called for tag '{tag}' (limit={limit})",
        )
        result = get_flows_for_tag(tag, limit=limit)
        log_info(
            logger,
            f"[INFO] MCP get_flows_by_tag returned {len(result)} flows for tag '{tag}'",
        )
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] get_flows_by_tag failed for tag '{tag}': {e}")
        return []


# ---------------------------------------------------------------------------
# Allow list / whitelist export
# ---------------------------------------------------------------------------


@app.tool("export_ignorelist")
def export_ignorelist():
    """
    Export all active ignore-list (allow-list) entries.
    These are flows that are suppressed from alerting.
    """
    try:
        log_info(logger, "[INFO] MCP export_ignorelist called")
        result = get_all_ignorelist_entries()
        log_info(logger, f"[INFO] MCP export_ignorelist returned {len(result)} entries")
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] export_ignorelist failed: {e}")
        return []


@app.tool("export_whitelisted_hosts")
def export_whitelisted_hosts():
    """
    Export all hosts that have the whitelisted flag set.
    These hosts are excluded from threat-detection processing.
    """
    try:
        log_info(logger, "[INFO] MCP export_whitelisted_hosts called")
        result = get_whitelisted_localhosts()
        log_info(
            logger, f"[INFO] MCP export_whitelisted_hosts returned {len(result)} hosts"
        )
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] export_whitelisted_hosts failed: {e}")
        return []


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio

    log_info(logger, "[INFO] MCP server starting on 0.0.0.0:8030")
    try:
        asyncio.run(
            app.run_http_async(
                host="0.0.0.0",
                port=8030,
                show_banner=False,
                # Prevent uvicorn from calling logging.config.dictConfig() on startup,
                # which would reinstall its own colored formatters over our plain setup.
                uvicorn_config={"log_config": None},
            )
        )
    except Exception as e:
        log_error(logger, f"[ERROR] MCP server failed: {e}")
