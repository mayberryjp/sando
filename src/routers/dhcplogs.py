import logging
import re
import sqlite3

from bottle import request, response

from src.database.dhcplogs import get_dhcp_logs
from src.utils.locallogging import log_error, log_warn


def setup_dhcplogs_routes(app):
    @app.get("/api/dhcp/logs")
    def dhcp_logs():
        logger = logging.getLogger(__name__)
        response.content_type = "application/json"
        try:
            pagination = {}
            for name in ("limit", "offset"):
                raw = request.query.get(name)
                if raw is not None:
                    if not re.fullmatch(r"[0-9]+", raw):
                        raise ValueError(f"{name} must be a non-negative integer")
                    pagination[name] = int(raw)
                    if pagination[name] > 9223372036854775807:
                        raise ValueError(f"{name} exceeds SQLite's integer range")
            filters = {
                name: request.query.get(name)
                for name in ("client_mac", "event", "transaction_id", "interface")
                if name in request.query
            }
            mac = filters.get("client_mac")
            if mac is not None and not re.fullmatch(
                r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac
            ):
                raise ValueError("client_mac must be a colon-separated MAC address")
            transaction = filters.get("transaction_id")
            if transaction is not None and not re.fullmatch(
                r"[0-9a-fA-F]{8}", transaction
            ):
                raise ValueError("transaction_id must contain eight hexadecimal digits")
            for name in ("event", "interface"):
                if name in filters and not filters[name]:
                    raise ValueError(f"{name} must not be empty")
        except ValueError as exc:
            log_warn(logger, f"[WARN] Invalid DHCP log query: {exc}")
            response.status = 400
            return {"error": str(exc)}
        try:
            return get_dhcp_logs(**filters, **pagination)
        except sqlite3.Error as exc:
            log_error(logger, f"[ERROR] Failed to retrieve DHCP logs: {exc}")
            response.status = 500
            return {"error": "Failed to retrieve DHCP logs"}
