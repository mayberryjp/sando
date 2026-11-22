import json
import logging
import sqlite3

from src.database.core import connect_to_db, disconnect_from_db
from src.utils.locallogging import log_error, log_info


def get_routers(config_dict, ip_version=None):
    """
    Extracts a set of router IP addresses from the LocalNetworks config entry.
    Args:
        config_dict (dict): Configuration dictionary containing 'LocalNetworks' as a JSON array.
        ip_version (int, optional): Filter by IP version (4 or 6). None returns all.
    Returns:
        set: Set of router IP addresses.
    """
    logger = logging.getLogger(__name__)
    raw = config_dict.get("LocalNetworks", "[]")
    try:
        scopes = json.loads(raw)
        result = set()
        for scope in scopes:
            if "router" not in scope or not scope["router"]:
                continue
            v = scope.get("ip_version", 4)
            if isinstance(v, str):
                v = 4 if v.lower() in ("ipv4", "4") else 6
            if ip_version is None or v == ip_version:
                result.add(scope["router"])
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] Could not parse LocalNetworks for routers: {e}")
        return set()


def get_local_network_cidrs(config_dict):
    """
    Extracts a set of CIDR strings from the LocalNetworks config entry.
    Each scope that is missing an ip_version flag defaults to 4.
    Args:
        config_dict (dict): Configuration dictionary containing 'LocalNetworks' as a JSON array.
    Returns:
        set: Set of CIDR strings.
    """
    logger = logging.getLogger(__name__)
    raw = config_dict.get("LocalNetworks", "[]")
    try:
        scopes = json.loads(raw)
        result = set()
        for scope in scopes:
            if "cidr" in scope:
                if "ip_version" not in scope:
                    scope["ip_version"] = 4
                else:
                    # Normalize: accept "IPv4"/4 as 4, "IPv6"/6 as 6
                    v = scope["ip_version"]
                    if isinstance(v, str):
                        scope["ip_version"] = 4 if v.lower() in ("ipv4", "4") else 6
                result.add(scope["cidr"])
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] Could not parse LocalNetworks: {e}")
        return set()


def get_local_networks(config_dict, *, strict=False):
    """
    Extracts local network scopes from the LocalNetworks config entry.
    Each scope that is missing an ip_version flag defaults to 4.
    Args:
        config_dict (dict): Configuration dictionary containing 'LocalNetworks' as a JSON array.
        strict (bool): Raise on malformed configuration instead of returning an empty list.
    Returns:
        list: Local network scope dictionaries with normalized ip_version values.
    """
    logger = logging.getLogger(__name__)
    raw = config_dict.get("LocalNetworks", "[]")
    try:
        scopes = json.loads(raw)
        if not isinstance(scopes, list):
            if strict:
                raise ValueError("LocalNetworks must be a JSON array")
            log_error(
                logger, "[ERROR] Could not parse LocalNetworks: expected a JSON array"
            )
            return []

        result = []
        for scope in scopes:
            if not isinstance(scope, dict) or "cidr" not in scope:
                if strict:
                    raise ValueError("Each LocalNetworks entry must contain a cidr")
                continue

            network = dict(scope)
            v = network.get("ip_version", 4)
            if isinstance(v, str):
                v = 4 if v.lower() in ("ipv4", "4") else 6
            network["ip_version"] = v
            result.append(network)
        return result
    except Exception as e:
        log_error(logger, f"[ERROR] Could not parse LocalNetworks: {e}")
        if strict:
            raise
        return []


def get_config_settings():
    """Read configuration settings from the configuration database into a dictionary."""
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("configuration")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to configuration database")
            return None

        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM configuration")
        config_dict = dict(cursor.fetchall())
        log_info(
            logger,
            f"[INFO] Successfully loaded {len(config_dict)} configuration settings",
        )
        return config_dict
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error reading configuration database: {e}")
        return None
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_config_setting(key, value, silent=False):
    """
    Insert or update a configuration setting in the database.

    Args:
        key (str): The configuration key
        value (str): The configuration value

    Returns:
        bool: True if the operation was successful, False otherwise
    """
    logger = logging.getLogger(__name__)

    try:
        # Connect to the configuration database
        conn = connect_to_db("configuration")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to configuration database")
            return False

        cursor = conn.cursor()

        # Insert or replace the configuration setting
        cursor.execute(
            """
            INSERT OR REPLACE INTO configuration (key, value, last_changed)
            VALUES (?, ?, datetime('now', 'localtime'))
        """,
            (key, value),
        )

        # Commit the changes
        conn.commit()

        if not silent:
            log_info(
                logger, f"[INFO] Successfully updated configuration setting: {key}"
            )
        return True

    except sqlite3.Error as e:
        log_error(
            logger, f"[ERROR] Database error while updating configuration setting: {e}"
        )
        return False
    except Exception as e:
        log_error(
            logger,
            f"[ERROR] Unexpected error while updating configuration setting: {e}",
        )
        return False
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)


def update_flow_metrics(last_packets, last_flows, last_bytes, source=None):
    """
    Update flow metrics in the configuration database.
    Stores/updates: Total Packets, Total Flows, Total Bytes, Last Packets, Last Flows, Last Bytes, Last Flow Seen.

    Args:
        last_packets (int): Number of packets in the last interval
        last_flows (int): Number of flows in the last interval
        last_bytes (int): Number of bytes in the last interval
        source (str): Collector name, used to aggregate independent last intervals.

    Returns:
        bool: True if all updates were successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    conn = None
    try:
        conn = connect_to_db("configuration")
        if not conn:
            raise sqlite3.OperationalError("Unable to connect to configuration database")
        conn.execute("BEGIN IMMEDIATE")
        config = dict(conn.execute("SELECT key, value FROM configuration").fetchall())
        total_packets = int(config.get("TotalPackets", 0))
        total_flows = int(config.get("TotalFlows", 0))
        total_bytes = int(config.get("TotalBytes", 0))

        updates = {
            "TotalPackets": total_packets + last_packets,
            "TotalFlows": total_flows + last_flows,
            "TotalBytes": total_bytes + last_bytes,
            "LastPackets": last_packets,
            "LastFlows": last_flows,
            "LastBytes": last_bytes,
        }
        if source is not None:
            if source not in ("netflow", "ipfix"):
                raise ValueError(f"Unknown collector metrics source: {source}")
            for suffix, value in (
                ("Packets", last_packets), ("Flows", last_flows), ("Bytes", last_bytes),
            ):
                key = f"{source}Last{suffix}"
                updates[key] = value
                other = "ipfix" if source == "netflow" else "netflow"
                updates[f"Last{suffix}"] = value + int(config.get(f"{other}Last{suffix}", 0))

        from datetime import datetime

        last_flow_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if last_flows > 0 and last_packets > 0 and last_bytes > 0:
            updates["LastFlowSeen"] = last_flow_seen
        conn.executemany(
            """
            INSERT INTO configuration (key, value, last_changed)
            VALUES (?, ?, datetime('now', 'localtime'))
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value, last_changed = excluded.last_changed
            """,
            [(key, str(value)) for key, value in updates.items()],
        )
        conn.commit()
        log_info(
            logger,
            f"[INFO] Successfully updated flow metrics. Packets: {last_packets}, Flows: {last_flows}, Bytes: {last_bytes}",
        )
        return True
    except (sqlite3.Error, ValueError, TypeError) as e:
        if conn:
            conn.rollback()
        log_error(logger, f"[ERROR] Exception in update_flow_metrics: {e}")
        return False
    finally:
        if conn:
            disconnect_from_db(conn)


def get_all_configuration():
    """
    Return all configuration records as a list of dicts with key, value, and last_changed.
    """
    logger = logging.getLogger(__name__)
    try:
        conn = connect_to_db("configuration")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to configuration database")
            return []
        cursor = conn.cursor()
        cursor.execute("SELECT key, value, last_changed FROM configuration")
        columns = [col[0] for col in cursor.description]
        rows = cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Error reading configuration database: {e}")
        return []
    finally:
        if "conn" in locals() and conn:
            disconnect_from_db(conn)
