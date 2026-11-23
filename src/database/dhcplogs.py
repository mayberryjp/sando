import json
import sqlite3
import time
from datetime import datetime

from src.const import CONST_DHCPLOG_RETENTION_DAYS
from src.database.core import connect_to_db, disconnect_from_db


def _connect():
    conn = connect_to_db("dhcplogs")
    if conn is None:
        raise sqlite3.OperationalError("DHCP log database is unavailable")
    return conn


def _expire(conn):
    conn.execute(
        "DELETE FROM dhcplogs WHERE timestamp < ?",
        (time.time() - CONST_DHCPLOG_RETENTION_DAYS * 86400,),
    )


def delete_aged_dhcp_logs():
    conn = _connect()
    try:
        with conn:
            _expire(conn)
    finally:
        disconnect_from_db(conn)


def insert_dhcp_log(event, *, interface=None, dhcp_message=None, peer=None,
                    transaction_id=None, client_mac=None, reason=None, details=None):
    conn = _connect()
    try:
        with conn:
            _expire(conn)
            conn.execute(
                """INSERT INTO dhcplogs (
                    timestamp, interface, event, dhcp_message, peer,
                    transaction_id, client_mac, reason, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    time.time(), interface, event, dhcp_message, peer,
                    transaction_id, client_mac.upper() if client_mac else None,
                    reason, json.dumps(details if details is not None else {}),
                ),
            )
    finally:
        disconnect_from_db(conn)


def get_dhcp_logs(*, client_mac=None, event=None, transaction_id=None,
                  interface=None, limit=None, offset=0):
    clauses = []
    params = []
    for column, value in (
        ("client_mac", client_mac.upper() if client_mac else None),
        ("event", event),
        ("transaction_id", transaction_id.lower() if transaction_id else None),
        ("interface", interface),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    conn = _connect()
    try:
        conn.row_factory = sqlite3.Row
        with conn:
            _expire(conn)
            total = conn.execute(
                "SELECT COUNT(*) FROM dhcplogs" + where, params
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM dhcplogs" + where
                + " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
                params + [limit if limit is not None else -1, offset],
            ).fetchall()
        logs = []
        for row in rows:
            item = dict(row)
            item["timestamp"] = datetime.fromtimestamp(
                item["timestamp"]
            ).astimezone().isoformat(timespec="milliseconds")
            item["details"] = json.loads(item["details"])
            logs.append(item)
        return {"logs": logs, "total": total, "limit": limit, "offset": offset}
    finally:
        disconnect_from_db(conn)
