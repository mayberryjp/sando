import os
import sys
from database.core import connect_to_db, disconnect_from_db
from pathlib import Path
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *

def update_all_flows(rows, config_dict):
    """Update allflows.db with the rows from newflows.db."""
    logger = logging.getLogger(__name__)
    conn = connect_to_db(CONST_CONSOLIDATED_DB, "allflows")
    total_packets = 0
    total_bytes = 0

    if conn:
        try:
            allflows_cursor = conn.cursor()
            for row in rows:
                src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_, flow_start, flow_end, last_seen, times_seen, tags = row
                total_packets += packets
                total_bytes += bytes_

                # Use datetime('now', 'localtime') for the current timestamp
                allflows_cursor.execute("""
                    INSERT INTO allflows (
                        src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, flow_start, flow_end, times_seen, last_seen, tags
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'), datetime('now', 'localtime'), 1, datetime('now', 'localtime'), ?)
                    ON CONFLICT(src_ip, dst_ip, src_port, dst_port, protocol)
                    DO UPDATE SET
                        packets = packets + excluded.packets,
                        bytes = bytes + excluded.bytes,
                        flow_end = excluded.flow_end,
                        times_seen = times_seen + 1,
                        last_seen = datetime('now', 'localtime'),
                        tags = excluded.tags
                """, (src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_, tags))
            conn.commit()
            log_info(logger, f"[INFO] Updated {CONST_CONSOLIDATED_DB} with {len(rows)} rows.")
        except sqlite3.Error as e:
            log_error(logger, f"[ERROR] Error updating {CONST_CONSOLIDATED_DB}: {e}")
        finally:
            disconnect_from_db(conn)
        log_info(logger, f"[INFO] Latest collection results packets: {total_packets} for bytes {total_bytes}")

    disconnect_from_db(conn)

def update_tag_to_allflows(table_name, tag, src_ip, dst_ip, dst_port):
    """
    Update the tag for a specific row in the database.

    Args:
        db_name (str): The database name.
        table_name (str): The table name.
        tag (str): The tag to add.
        src_ip (str): The source IP address.
        dst_ip (str): The destination IP address.
        dst_port (int): The destination port.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    logger = logging.getLogger(__name__)
    conn = connect_to_db(CONST_CONSOLIDATED_DB, table_name)
    if not conn:
        log_error(logger, f"[ERROR] Unable to connect to database: {CONST_CONSOLIDATED_DB}")
        return False

    try:
        cursor = conn.cursor()

        # Retrieve the existing tag
        cursor.execute(f"""
            SELECT tags FROM {table_name}
            WHERE src_ip = ? AND dst_ip = ? AND dst_port = ?
            AND tags not like '%DeadConnectionDetection%'
        """, (src_ip, dst_ip, dst_port))
        result = cursor.fetchone()

        existing_tag = result[0] if result and result[0] else ""  # Get the existing tag or default to an empty string

        # Append the new tag to the existing tag
        updated_tag = f"{existing_tag}{tag}" if existing_tag else tag

        # Update the tag in the database
        cursor.execute(f"""
            UPDATE {table_name}
            SET tags = ?
            WHERE src_ip = ? AND dst_ip = ? AND dst_port = ?
        """, (updated_tag, src_ip, dst_ip, dst_port))
        conn.commit()

        log_info(logger, f"[INFO] Tag '{tag}' added to flow: {src_ip} -> {dst_ip}:{dst_port}. Updated tag: '{updated_tag}'")
        return True
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Failed to add tag to flow: {e}")
        return False
    finally:
        disconnect_from_db(conn)

def get_flows_by_source_ip(src_ip):
    """
    Retrieve all flows from a specific source IP address, grouped by destination.
    
    Args:
        src_ip (str): The source IP address to search for
        
    Returns:
        list: A list of dictionaries containing aggregated flow data for each destination,
              ordered by total_bytes in descending order.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the allflows database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "allflows")
        if not conn:
            log_error(logger, f"[ERROR] Unable to connect to allflows database.")
            return []

        cursor = conn.cursor()
        
        # Query all flows from the specified source IP
        cursor.execute("""
         SELECT dst_ip, dst_port, protocol,
                   sum(times_seen) as flow_count,
                   SUM(packets) as total_packets,
                   SUM(bytes) as total_bytes,
                   MAX(last_seen) as last_flow,
                   MIN(flow_start) as first_flow
            FROM allflows 
            WHERE src_ip = ?
            GROUP BY dst_ip, dst_port, protocol
            ORDER BY total_bytes DESC
        """, (src_ip,))
        
        rows = cursor.fetchall()
            
        #log_info(logger, f"[INFO] Retrieved {len(rows)} flow records for source IP {src_ip}.")
        return rows
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving flows for source IP {src_ip}: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving flows for source IP {src_ip}: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_dead_connections_from_database():
    """
    Identify potential dead connections in the network by finding flows that have
    traffic in one direction but not in the reverse direction.
    
    Returns:
        list: A list of dictionaries containing information about potential dead connections.
              Each dictionary includes initiator_ip, responder_ip, responder_port, 
              protocol, tags, and packet counts.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the allflows database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "allflows")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to allflows database.")
            return []

        cursor = conn.cursor()
        
        # Execute the complex query to identify potential dead connections
        cursor.execute("""
               WITH ConnectionPairs AS (
                    SELECT 
                        a1.src_ip as initiator_ip,
                        a1.dst_ip as responder_ip,
                        a1.src_port as initiator_port,
                        a1.dst_port as responder_port,
                        a1.protocol as connection_protocol,
                        a1.packets as forward_packets,
                        a1.bytes as forward_bytes,
                        a1.times_seen as forward_seen,
                        a1.tags as row_tags,
                        COALESCE(a2.packets, 0) as reverse_packets,
                        COALESCE(a2.bytes, 0) as reverse_bytes,
                        COALESCE(a2.times_seen, 0) as reverse_seen
                    FROM allflows a1
                    LEFT JOIN allflows a2 ON 
                        a2.src_ip = a1.dst_ip 
                        AND a2.dst_ip = a1.src_ip
                        AND a2.src_port = a1.dst_port
                        AND a2.dst_port = a1.src_port
                        AND a2.protocol = a1.protocol
                )
                SELECT 
                    initiator_ip,
                    responder_ip,
					initiator_port,
                    responder_port,
                    connection_protocol,
                    row_tags,
                    COUNT(*) as connection_count,
                    sum(forward_packets) as f_packets,
                    sum(reverse_packets) as r_packets,
					sum(forward_bytes) as f_bytes,
					sum(reverse_bytes) as r_bytes
                FROM ConnectionPairs
                WHERE connection_protocol=6 -- Exclude ICMP and IGMP
                AND row_tags not like '%DeadConnectionDetection%'
                AND responder_ip NOT LIKE '224%'  -- Exclude multicast
                AND responder_ip NOT LIKE '239%'  -- Exclude multicast
                AND responder_ip NOT LIKE '255%'  -- Exclude broadcast
                GROUP BY initiator_ip, responder_ip, responder_port, connection_protocol
                HAVING 
                    f_packets > 2
                    AND r_packets < 1
        """)
        
        raw_rows = cursor.fetchall()
        
        # Restructure rows to match required field order
        restructured_rows = []
        for row in raw_rows:
            initiator_ip = row[0]        # src_ip
            responder_ip = row[1]        # dst_ip
            initiator_port = row[2]      # src_port
            responder_port = row[3]      # dst_port
            protocol = row[4]            # protocol
            tags = row[5]                # tags
            # connection_count = row[6]  # Not used in the restructured output
            packets = row[7]             # forward_packets
            bytes_ = row[9]             # forward_bytes (f_bytes)
            
            # Create default values for missing fields
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            flow_start = current_time    # Placeholder
            flow_end = current_time      # Placeholder
            last_seen = current_time     # Placeholder
            times_seen = row[6]              # Default value
            
            # Create a restructured row with the requested field order
            restructured_row = (
                initiator_ip,             # src_ip
                responder_ip,             # dst_ip
                initiator_port,    
               responder_port,           # dst_port
                protocol,                 # protocol
                packets,                  # packets
                bytes_,                   # bytes
                flow_start,               # flow_start
                flow_end,                 # flow_end
                last_seen,                # last_seen
                times_seen,               # times_seen
                tags                      # tags
            )
            restructured_rows.append(restructured_row)
            

            
        log_info(logger, f"[INFO] Identified {len(restructured_rows)} potential dead connections.")
        return restructured_rows
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while querying dead connections: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while querying dead connections: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)


def get_tag_statistics(local_ip):
    """
    Retrieve statistics about tags used in the allflows table for a specific IP address,
    using a recursive query to split multi-tag entries into individual tags.
    
    Args:
        local_ip (str): The IP address to filter results by (as source or destination)
        
    Returns:
        dict: A dictionary with tags as keys and statistics as values (count, first_seen, last_seen).
              Returns an empty dictionary if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "allflows")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to database for tag statistics.")
            return {}
            
        conn.create_function("TRIM", 1, lambda x: x.strip() if x else "")
        cursor = conn.cursor()
        
        # Use run_timed_query for the recursive query
        query = """
         WITH RECURSIVE split_tags(src_ip, dst_ip, flow_start, last_seen, tag, rest) AS (
              SELECT
                src_ip,
                dst_ip,
                flow_start,
                last_seen,
                '',                     -- Initial tag (empty)
                tags || ';'             -- Append semicolon to simplify parsing
              FROM allflows
              WHERE tags IS NOT NULL 
                AND tags != ''
                AND (src_ip = ? OR dst_ip = ?)  -- Filter by local_ip
              
              UNION ALL
              
              SELECT
                src_ip,
                dst_ip,
                flow_start,
                last_seen,
                TRIM(substr(rest, 0, instr(rest, ';'))),
                substr(rest, instr(rest, ';') + 1)
              FROM split_tags
              WHERE rest != ''
            )
            SELECT 
              tag,
              COUNT(*) as occurrence_count,
              datetime(MIN(flow_start), 'localtime') as first_seen,
              datetime(MAX(last_seen), 'localtime') as last_seen
            FROM split_tags
            WHERE tag != ''
            GROUP BY tag
            ORDER BY occurrence_count DESC
        """
        
        # Execute the query and time it
        from database.core import run_timed_query
        rows, execution_time = run_timed_query(
            cursor, 
            query, 
            params=(local_ip, local_ip),  # Pass local_ip twice for src_ip and dst_ip conditions
            description=f"Tag Statistics for IP {local_ip}", 
            fetch_all=True
        )
        
        # Create dictionary mapping tag -> statistics
        tag_stats = {}
        for tag, count, first_seen, last_seen in rows:
            tag = tag.strip()
            if tag:  # Skip empty tags
                tag_stats[tag] = {
                    'count': count,
                    'first_seen': first_seen,
                    'last_seen': last_seen
                }
        
        log_info(logger, f"[INFO] Retrieved statistics for {len(tag_stats)} unique tags for IP {local_ip} in {execution_time:.2f} ms")
        return tag_stats
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving tag statistics for IP {local_ip}: {e}")
        return {}
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving tag statistics for IP {local_ip}: {e}")
        return {}
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)


def apply_ignorelist_entry(ignorelist_id, src_ip, dst_ip, dst_port, protocol):
    """
    Apply an ignorelist entry by updating matching flows and removing matching alerts.
    
    Args:
        ignorelist_id (str): The unique identifier for the ignorelist entry
        src_ip (str): Source IP address
        dst_ip (str): Destination IP address (supports * wildcard)
        dst_port (str): Destination port (supports * wildcard)
        protocol (str): Protocol (e.g., 'tcp', 'udp')
        
    Returns:
        tuple: (flows_updated, alerts_deleted) - Count of affected flows and alerts
    """
    logger = logging.getLogger(__name__)
    flows_updated = 0
    
    # Create the tag to add to flows
    ignore_tag = f"IgnoreList_{ignorelist_id};"
    
    try:
        # 1. Update matching flows in allflows table
        conn_flows = connect_to_db(CONST_CONSOLIDATED_DB, "allflows")
        if not conn_flows:
            log_error(logger, "[ERROR] Unable to connect to allflows database.")
            return 0
            
        cursor_flows = conn_flows.cursor()
        
        # Prepare SQL conditions and parameters based on wildcards
        flow_where_conditions = []
        flow_params = []
        
        if src_ip != "*":
            flow_where_conditions.append("src_ip = ?")
            flow_params.append(src_ip)
            
        if dst_ip != "*":
            flow_where_conditions.append("dst_ip = ?")
            flow_params.append(dst_ip)
            
        if dst_port != "*":
            flow_where_conditions.append("dst_port = ?")
            flow_params.append(dst_port)
            
        if protocol != "*":
            flow_where_conditions.append("protocol = ?")
            flow_params.append(protocol)
            
        # Construct WHERE clause
        flow_where_clause = " AND ".join(flow_where_conditions) if flow_where_conditions else "1=1"
        
        # Update query - handle tags field (could be NULL or empty)
        update_query = f"""
            UPDATE allflows
            SET tags = CASE
                WHEN tags IS NULL OR tags = '' THEN ?
                WHEN tags LIKE ? THEN tags  -- Already has the tag
                ELSE tags || ?  -- Append the tag
            END
            WHERE {flow_where_clause}
        """
        
        # Add parameters for the SET clause
        all_flow_params = [
            ignore_tag,  # For NULL or empty tags
            f"%{ignore_tag}%",  # For LIKE check
            ignore_tag,  # For appending
            *flow_params  # For WHERE conditions
        ]
        
        cursor_flows.execute(update_query, all_flow_params)
        flows_updated = cursor_flows.rowcount
        conn_flows.commit()
     
        log_info(logger, f"[INFO] Applied ignorelist entry {ignorelist_id}: Updated {flows_updated} flows")
        return (flows_updated)
    
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while applying ignorelist entry {ignorelist_id}: {e}")
        return 0
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while applying ignorelist entry {ignorelist_id}: {e}")
        return 0
    finally:
        if 'conn_flows' in locals() and conn_flows:
            disconnect_from_db(conn_flows)
