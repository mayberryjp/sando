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


def insert_dns_query(client_ip, domain, times_seen, datasource):
    """
    Insert or update a DNS query record in the dnsqueries database.
    
    Args:
        client_ip (str): The IP address of the client that made the DNS query
        domain (str): The domain name that was queried
        times_seen (int, optional): The number of times this query was seen (default: 1)
        
    Returns:
        bool: True if the insertion/update was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the dnsqueries database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "dnsqueries")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to dnsqueries database.")
            return False
            
        cursor = conn.cursor()
        
        # Insert or update the DNS query record
        cursor.execute("""
            INSERT INTO dnsqueries (client_ip, domain, type, times_seen, first_seen, last_seen, datasource, last_refresh)
            VALUES (?, ?, 'A', ?, datetime('now', 'localtime'), datetime('now', 'localtime'), ?, datetime('now', 'localtime'))
            ON CONFLICT(client_ip, domain, type, datasource)
            DO UPDATE SET
                last_seen = datetime('now', 'localtime'),
                times_seen = times_seen + excluded.times_seen
        """, (client_ip, domain, times_seen, datasource))
        
        # Commit the changes
        conn.commit()
        
        #log_info(logger, f"[INFO] Successfully inserted/updated DNS query record for client {client_ip}, domain {domain}")
        return True
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while inserting DNS query record: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while inserting DNS query record: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_client_dns_queries(client_ip):
    """
    Retrieve all DNS queries made by a specific client IP address.
    
    Args:
        client_ip (str): The IP address of the client
        
    Returns:
        list: A list of dictionaries containing domain, query_count, last_query, and first_query
              for each domain queried by the client, ordered by query_count descending.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:

        # Connect to the dnsqueries database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "dnsqueries")
        if not conn:
            log_error(logger, f"[ERROR] Unable to connect to Pi-hole database.")
            return []

        dns_cursor = conn.cursor()
        
        # Query for all domains queried by the client IP
        dns_cursor.execute("""
            SELECT domain, sum(times_seen) as query_count, 
                   MAX(last_seen) as last_query,
                   MIN(first_seen) as first_query
            FROM dnsqueries 
            WHERE client_ip = ?
            GROUP BY domain
            ORDER BY query_count DESC
        """, (client_ip,))
        
        rows = dns_cursor.fetchall()
        
        #log_info(logger, f"[INFO] Retrieved {len(rows)} DNS query records for client IP {client_ip}.")
        return rows
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving DNS queries for client IP {client_ip}: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving DNS queries for client IP {client_ip}: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)


def insert_dns_queries_batch(queries, datasource):
    """
    Insert or update multiple DNS query records in the dnsqueries database in a single batch operation.
    
    Args:
        queries (list): List of dictionaries containing DNS query information.
                        Each dictionary should have 'client_ip', 'domain', and 'blocked' keys.
                        
    Returns:
        tuple: (bool, int) - Success status and count of records processed
    """
    logger = logging.getLogger(__name__)
    
    if not queries:
        return True, 0
    
    try:
        # Connect to the dnsqueries database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "dnsqueries")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to dnsqueries database for batch insert.")
            return False, 0
            
        cursor = conn.cursor()
        
        # Prepare the batch data
        batch_data = []
        for query in queries:
            client_ip = query.get('client_ip')
            domain = query.get('domain')
            times_seen = query.get('times_seen', 1)
            
            if not client_ip or not domain:
                continue
                
            batch_data.append((client_ip, domain, 'A', times_seen, datasource))
        
        # Check if we have any valid records after filtering
        if not batch_data:
            return True, 0
            
        # Execute the batch insert with ON CONFLICT handling
        cursor.executemany("""
            INSERT INTO dnsqueries (client_ip, domain, type, times_seen, first_seen, last_seen, datasource, last_refresh)
            VALUES (?, ?, ?, ?, datetime('now', 'localtime'), datetime('now', 'localtime'), ?, datetime('now', 'localtime'))
            ON CONFLICT(client_ip, domain, type, datasource)
            DO UPDATE SET
                last_seen = datetime('now', 'localtime'),
                times_seen = times_seen + excluded.times_seen
        """, batch_data)
        
        # Commit the transaction
        conn.commit()
        
        record_count = len(batch_data)
        log_info(logger, f"[INFO] Successfully batch inserted/updated {record_count} DNS query records")
        return True, record_count
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error during dnsqueries batch insert: {e}")
        return False, 0
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error during dnsqueries batch insert: {e}")
        return False, 0
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)


def update_dns_query_response(response, id):
    """
    Update the response field for a specific DNS query record.
    
    Args:
        client_ip (str): The IP address of the client that made the DNS query
        domain (str): The domain name that was queried
        query_type (str): The type of query (e.g., 'A', 'AAAA', 'MX')
        response (str): The DNS response to store
        
    Returns:
        bool: True if the update was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the dnsqueries database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "dnsqueries")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to dnsqueries database.")
            return False
            
        cursor = conn.cursor()

        # Update the response field for the matching record
        cursor.execute("""
            UPDATE dnsqueries
            SET response = ?, last_refresh = datetime('now', 'localtime')
            WHERE id = ?
        """, (response, id))
                
        # Commit the changes
        conn.commit()
        
        return True
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while updating DNS query response: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while updating DNS query response: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_dnsqueries_without_responses():
    """
    Retrieve DNS queries where the response is NULL or empty.
    
    Args:
        limit (int, optional): Maximum number of records to return. Default is 100.
        offset (int, optional): Number of records to skip for pagination. Default is 0.
        
    Returns:
        list: A list of dictionaries containing DNS query records with empty responses,
              ordered by last_seen descending.
              Returns an empty list if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the dnsqueries database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "dnsqueries")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to dnsqueries database.")
            return []

        cursor = conn.cursor()
        
        # Query for DNS queries with NULL or empty responses, refresh every 90 days or TIMEDOUT
        cursor.execute("""
            SELECT id, domain, type
            FROM dnsqueries 
            WHERE response IS NULL 
               OR response = ''
               OR date(last_refresh) <= date('now', '-90 days')
               OR response = 'TIMEOUT'
            ORDER BY last_seen DESC
        """)
        
        rows = cursor.fetchall()
        # Fetch results and convert to list of dictionaries

        log_info(logger, f"[INFO] Retrieved {len(rows)} DNS queries with empty responses")
        return rows
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving DNS queries without responses: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving DNS queries without responses: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)



def get_ip_to_domain_mapping():
    """
    Retrieve a mapping of IP addresses to their corresponding domain names
    from the dnsqueries table, using a recursive query to split multi-IP responses.
    
    Returns:
        dict: A dictionary with IP addresses as keys and domain names as values.
              Returns an empty dictionary if no data is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "dnsqueries")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to database for IP-domain mapping.")
            return {}
            
        conn.create_function("TRIM", 1, lambda x: x.strip() if x else "")
        cursor = conn.cursor()
        
        # Recursive query to split comma-separated IP addresses
        cursor.execute("""
            WITH RECURSIVE split(id, domain, ip_address, rest) AS (
              SELECT
                id,
                domain,
                '',                     -- Initial IP (empty)
                response || ','         -- Append comma to simplify parsing
              FROM dnsqueries
              WHERE response IS NOT NULL 
                AND response != '' 
                AND response != 'TIMEOUT'
              
              UNION ALL
              
              SELECT
                id,
                domain,
                TRIM(substr(rest, 0, instr(rest, ','))),
                substr(rest, instr(rest, ',') + 1)
              FROM split
              WHERE rest != ''
            )
            SELECT ip_address, domain
            FROM split
            WHERE ip_address != ''
        """)
        
        rows = cursor.fetchall()
        
        # Create dictionary mapping IP address -> domain
        ip_to_domain = {}
        for ip, domain in rows:
            # If IP is valid (check with simple validation)
            if ip and '.' in ip and not (ip.startswith(';') or ip.startswith('#')):
                ip_to_domain[ip.strip()] = domain
        
        log_info(logger, f"[INFO] Created IP-to-domain mapping with {len(ip_to_domain)} entries")
        return ip_to_domain
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while creating IP-to-domain mapping: {e}")
        return {}
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while creating IP-to-domain mapping: {e}")
        return {}
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)