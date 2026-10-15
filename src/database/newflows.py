import logging
import sqlite3

from src.database.core import connect_to_db, disconnect_from_db
from src.utils.locallogging import log_error, log_info


def get_new_flows(clear=False):
    """
    Retrieve all records from the flows table in the newflows database.

    Args:
        clear (bool): If True, delete the returned rows in the same transaction
            so flows written concurrently by the collector are never lost.

    Returns:
        list: A list of lists containing all flow records,
              or an empty list if an error occurs.
    """

    logger = logging.getLogger(__name__)
    conn = None

    try:
        # Connect to the newflows database
        conn = connect_to_db("newflows")
        if not conn:
            log_error(logger, "[ERROR] Failed to connect to newflows database")
            return []

        # Execute the query
        cursor = conn.cursor()
        if clear:
            # Take the write lock up front; Python's implicit transactions would not.
            conn.isolation_level = None
            cursor.execute("BEGIN IMMEDIATE")
        try:
            cursor.execute("SELECT * FROM newflows")
            rows = cursor.fetchall()
            if clear:
                cursor.execute("DELETE FROM newflows")
                cursor.execute("COMMIT")
        except Exception:
            if clear:
                cursor.execute("ROLLBACK")
            raise

        # Convert tuple rows to lists
        rows = [list(row) for row in rows]

        log_info(
            logger, f"[INFO] Retrieved {len(rows)} flow records from newflows database"
        )
        return rows

    except Exception as e:
        log_error(
            logger, f"[ERROR] Failed to retrieve flows from newflows database: {e}"
        )
        return []

    finally:
        # Ensure database connection is closed
        if conn:
            disconnect_from_db(conn)


def update_new_flows(records):
    """Upsert all records in a single transaction."""
    if not records:
        return

    conn = connect_to_db("newflows")
    if not conn:
        raise sqlite3.OperationalError("Failed to connect to newflows database")

    try:
        with conn:
            conn.executemany(
                """
        INSERT INTO newflows (
            src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, flow_start, flow_end, last_seen, times_seen, tags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'), datetime('now', 'localtime'), datetime('now', 'localtime'), 1,?)
        ON CONFLICT(src_ip, dst_ip, src_port, dst_port, protocol)
        DO UPDATE SET
            packets = packets + excluded.packets,
            bytes = bytes + excluded.bytes,
            flow_end = excluded.flow_end,
            last_seen = excluded.last_seen,
            times_seen = times_seen + 1
    """,
                [
                    (
                        r["src_ip"],
                        r["dst_ip"],
                        r["src_port"],
                        r["dst_port"],
                        r["protocol"],
                        r["packets"],
                        r["bytes"],
                        r["tags"],
                    )
                    for r in records
                ],
            )
    finally:
        disconnect_from_db(conn)
