import json
import logging
import os
import sys

from bottle import Bottle, request, response, run  # noqa: E402

from src.database.alerts import get_all_alerts, get_all_alerts_by_ip  # noqa: E402
from src.database.configuration import get_all_configuration  # noqa: E402
from src.database.configuration import get_local_networks
from src.database.explore import (
    get_flows_for_country,
    get_flows_for_ip,
    get_flows_for_port,
    get_flows_for_tag,
)
from src.database.explore import get_top_flows as db_get_top_flows  # noqa: E402
from src.database.explore import search_flows as db_search_flows
from src.database.ignorelist import get_all_ignorelist_entries  # noqa: E402
from src.database.localhosts import get_localhost_as_dict, get_localhosts_all  # noqa: E402
from src.database.localhosts import get_whitelisted_localhosts
from src.utils.locallogging import log_error, log_info  # noqa: E402

os.environ["PYTHONUNBUFFERED"] = "1"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

"""
Sando MCP Server — Bottle-based JSON-RPC 2.0 implementation.

Implements the MCP (Model Context Protocol) Streamable HTTP transport:
  POST /mcp  — JSON-RPC endpoint handling initialize, tools/list, tools/call

Available tools:
  Host investigation:
    list_hosts               - All known hosts with complete localhost details
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
    get_networks             - All configured local IPv4/IPv6 networks
    list_alerts              - All alerts (unfiltered)
"""


logger = logging.getLogger(__name__)

MCP_PORT = int(os.getenv("MCP_PORT", 8030))
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")

# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOLS = {}


def mcp_tool(name, description, parameters=None):
    """Decorator to register a function as an MCP tool."""
    if parameters is None:
        parameters = {"type": "object", "properties": {}}

    def decorator(func):
        TOOLS[name] = {
            "name": name,
            "description": description,
            "inputSchema": parameters,
            "function": func,
        }
        return func

    return decorator


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@mcp_tool(
    "list_configuration",
    "Return all configuration key/value pairs.",
)
def list_configuration(arguments):
    log_info(logger, "[INFO] MCP list_configuration called")
    result = get_all_configuration()
    log_info(logger, f"[INFO] MCP list_configuration returned {len(result)} items")
    return result


@mcp_tool(
    "get_networks",
    "Return configured local IPv4 and IPv6 networks.",
)
def get_networks(arguments):
    log_info(logger, "[INFO] MCP get_networks called")
    config_rows = get_all_configuration()
    config_dict = {row["key"]: row.get("value") for row in config_rows if "key" in row}
    result = get_local_networks(config_dict)
    log_info(logger, f"[INFO] MCP get_networks returned {len(result)} networks")
    return result


@mcp_tool(
    "list_alerts",
    "Return all alerts. Optionally filter to unacknowledged only.",
    {
        "type": "object",
        "properties": {
            "unacknowledged_only": {
                "type": "boolean",
                "description": "When true, only return alerts where acknowledged = 0.",
                "default": False,
            }
        },
    },
)
def list_alerts(arguments):
    unacknowledged_only = arguments.get("unacknowledged_only", False)
    log_info(
        logger,
        f"[INFO] MCP list_alerts called (unacknowledged_only={unacknowledged_only})",
    )
    alerts = get_all_alerts()
    if unacknowledged_only:
        alerts = [a for a in alerts if not a.get("acknowledged")]
    log_info(logger, f"[INFO] MCP list_alerts returned {len(alerts)} items")
    return alerts


@mcp_tool(
    "list_hosts",
    "Return all known hosts with complete localhost details.",
)
def list_hosts(arguments):
    log_info(logger, "[INFO] MCP list_hosts called")
    result = get_localhosts_all()
    log_info(logger, f"[INFO] MCP list_hosts returned {len(result)} hosts")
    return result


@mcp_tool(
    "get_host_alerts",
    "Return all alerts for a specific host IP address, most recent first.",
    {
        "type": "object",
        "properties": {
            "ip_address": {
                "type": "string",
                "description": "The IPv4 or IPv6 address of the host.",
            }
        },
        "required": ["ip_address"],
    },
)
def get_host_alerts(arguments):
    ip_address = arguments["ip_address"]
    log_info(logger, f"[INFO] MCP get_host_alerts called for {ip_address}")
    result = get_all_alerts_by_ip(ip_address)
    log_info(
        logger,
        f"[INFO] MCP get_host_alerts returned {len(result)} items for {ip_address}",
    )
    return result


@mcp_tool(
    "get_host",
    "Return a full profile for a host including its database record, open alerts, and top-10 flows by bytes.",
    {
        "type": "object",
        "properties": {
            "ip_address": {
                "type": "string",
                "description": "The IPv4 address or MAC address of the host.",
            }
        },
        "required": ["ip_address"],
    },
)
def get_host(arguments):
    ip_address = arguments["ip_address"]
    log_info(logger, f"[INFO] MCP get_host called for {ip_address}")
    result = {
        "host": get_localhost_as_dict(ip_address),
        "alerts": get_all_alerts_by_ip(ip_address),
        "top_flows": get_flows_for_ip(ip_address, limit=10),
    }
    log_info(
        logger,
        f"[INFO] MCP get_host returned host={'found' if result.get('host') else 'not found'}, "
        f"{len(result.get('alerts', []))} alerts, {len(result.get('top_flows', []))} flows for {ip_address}",
    )
    return result


@mcp_tool(
    "get_host_flows",
    "Return flows originating from or destined to a host, enriched with geo/ASN/DNS.",
    {
        "type": "object",
        "properties": {
            "ip_address": {
                "type": "string",
                "description": "Source or destination IP address.",
            },
            "limit": {
                "type": "integer",
                "description": "Max flows to return.",
                "default": 25,
            },
            "order_by": {
                "type": "string",
                "description": "'bytes' or 'packets'.",
                "default": "bytes",
            },
        },
        "required": ["ip_address"],
    },
)
def get_host_flows(arguments):
    ip_address = arguments["ip_address"]
    limit = arguments.get("limit", 25)
    order_by = arguments.get("order_by", "bytes")
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


@mcp_tool(
    "get_top_flows",
    "Return the top flows across all hosts, enriched with geo/ASN/DNS.",
    {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Max flows to return.",
                "default": 25,
            },
            "order_by": {
                "type": "string",
                "description": "'bytes' or 'packets'.",
                "default": "bytes",
            },
        },
    },
)
def get_top_flows(arguments):
    limit = arguments.get("limit", 25)
    order_by = arguments.get("order_by", "bytes")
    log_info(
        logger, f"[INFO] MCP get_top_flows called (limit={limit}, order_by={order_by})"
    )
    result = db_get_top_flows(limit=limit, order_by=order_by)
    log_info(logger, f"[INFO] MCP get_top_flows returned {len(result)} flows")
    return result


@mcp_tool(
    "search_flows",
    "Flexible flow search. All filters are optional and combined with AND logic.",
    {
        "type": "object",
        "properties": {
            "src_ip": {"type": "string", "description": "Filter by source IP."},
            "dst_ip": {"type": "string", "description": "Filter by destination IP."},
            "dst_port": {
                "type": "integer",
                "description": "Filter by destination port.",
            },
            "country": {
                "type": "string",
                "description": "Filter by country name (partial match).",
            },
            "tag": {
                "type": "string",
                "description": "Filter flows whose tags contain this string.",
            },
            "limit": {
                "type": "integer",
                "description": "Max rows to return.",
                "default": 50,
            },
        },
    },
)
def search_flows(arguments):
    src_ip = arguments.get("src_ip")
    dst_ip = arguments.get("dst_ip")
    dst_port = arguments.get("dst_port")
    country = arguments.get("country")
    tag = arguments.get("tag")
    limit = arguments.get("limit", 50)
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


@mcp_tool(
    "get_flows_by_country",
    "Return flows where the source or destination country matches.",
    {
        "type": "object",
        "properties": {
            "country": {
                "type": "string",
                "description": "Country name or partial name (case-insensitive).",
            },
            "limit": {
                "type": "integer",
                "description": "Max rows to return.",
                "default": 50,
            },
        },
        "required": ["country"],
    },
)
def get_flows_by_country(arguments):
    country = arguments["country"]
    limit = arguments.get("limit", 50)
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


@mcp_tool(
    "get_flows_by_port",
    "Return all flows on a specific destination port.",
    {
        "type": "object",
        "properties": {
            "port": {"type": "integer", "description": "Destination port number."},
            "limit": {
                "type": "integer",
                "description": "Max rows to return.",
                "default": 50,
            },
        },
        "required": ["port"],
    },
)
def get_flows_by_port(arguments):
    port = arguments["port"]
    limit = arguments.get("limit", 50)
    log_info(
        logger, f"[INFO] MCP get_flows_by_port called for port {port} (limit={limit})"
    )
    result = get_flows_for_port(port, limit=limit)
    log_info(
        logger,
        f"[INFO] MCP get_flows_by_port returned {len(result)} flows for port {port}",
    )
    return result


@mcp_tool(
    "get_flows_by_tag",
    "Return all flows that carry a specific tag (e.g. 'Geolocation', 'Reputation', 'TorNode').",
    {
        "type": "object",
        "properties": {
            "tag": {
                "type": "string",
                "description": "Tag string to search for (partial match).",
            },
            "limit": {
                "type": "integer",
                "description": "Max rows to return.",
                "default": 50,
            },
        },
        "required": ["tag"],
    },
)
def get_flows_by_tag(arguments):
    tag = arguments["tag"]
    limit = arguments.get("limit", 50)
    log_info(
        logger, f"[INFO] MCP get_flows_by_tag called for tag '{tag}' (limit={limit})"
    )
    result = get_flows_for_tag(tag, limit=limit)
    log_info(
        logger,
        f"[INFO] MCP get_flows_by_tag returned {len(result)} flows for tag '{tag}'",
    )
    return result


@mcp_tool(
    "export_ignorelist",
    "Export all active ignore-list (allow-list) entries.",
)
def export_ignorelist(arguments):
    log_info(logger, "[INFO] MCP export_ignorelist called")
    result = get_all_ignorelist_entries()
    log_info(logger, f"[INFO] MCP export_ignorelist returned {len(result)} entries")
    return result


@mcp_tool(
    "export_whitelisted_hosts",
    "Export all hosts that have the whitelisted flag set.",
)
def export_whitelisted_hosts(arguments):
    log_info(logger, "[INFO] MCP export_whitelisted_hosts called")
    result = get_whitelisted_localhosts()
    log_info(
        logger, f"[INFO] MCP export_whitelisted_hosts returned {len(result)} hosts"
    )
    return result


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

SERVER_INFO = {
    "name": "sando-mcp",
    "version": "2026.2.0",
}

CAPABILITIES = {
    "tools": {},
}


def jsonrpc_success(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def jsonrpc_error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


# ---------------------------------------------------------------------------
# Bottle app and MCP endpoint
# ---------------------------------------------------------------------------

app = Bottle()


@app.route("/mcp", method=["POST"])
def mcp_endpoint():
    """MCP Streamable HTTP transport — handles JSON-RPC 2.0 requests."""
    response.content_type = "application/json"

    try:
        body = request.json
    except Exception:
        return json.dumps(jsonrpc_error(None, -32700, "Parse error"))

    if not body or "method" not in body:
        return json.dumps(
            jsonrpc_error(body.get("id") if body else None, -32600, "Invalid request")
        )

    method = body.get("method")
    params = body.get("params", {})
    req_id = body.get("id")

    log_info(logger, f"[INFO] MCP request: method={method} id={req_id}")

    # --- initialize ---
    if method == "initialize":
        result = {
            "protocolVersion": "2025-03-26",
            "serverInfo": SERVER_INFO,
            "capabilities": CAPABILITIES,
        }
        return json.dumps(jsonrpc_success(req_id, result))

    # --- notifications/initialized ---
    if method == "notifications/initialized":
        return json.dumps(jsonrpc_success(req_id, {}))

    # --- tools/list ---
    if method == "tools/list":
        tool_list = []
        for t in TOOLS.values():
            tool_list.append(
                {
                    "name": t["name"],
                    "description": t["description"],
                    "inputSchema": t["inputSchema"],
                }
            )
        return json.dumps(jsonrpc_success(req_id, {"tools": tool_list}))

    # --- tools/call ---
    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name not in TOOLS:
            return json.dumps(
                jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name}")
            )

        try:
            result = TOOLS[tool_name]["function"](arguments)
            content = [{"type": "text", "text": json.dumps(result, default=str)}]
            return json.dumps(jsonrpc_success(req_id, {"content": content}))
        except Exception as e:
            log_error(logger, f"[ERROR] Tool {tool_name} failed: {e}")
            content = [{"type": "text", "text": json.dumps({"error": str(e)})}]
            return json.dumps(
                jsonrpc_success(req_id, {"content": content, "isError": True})
            )

    # --- unknown method ---
    return json.dumps(jsonrpc_error(req_id, -32601, f"Method not found: {method}"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    log_info(logger, f"[INFO] MCP server starting on {MCP_HOST}:{MCP_PORT}")
    run(app, host=MCP_HOST, port=MCP_PORT, server="waitress", quiet=True)


if __name__ == "__main__":
    main()
