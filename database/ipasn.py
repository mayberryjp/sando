import os
import sys
from database.core import connect_to_db, disconnect_from_db, run_timed_query
from pathlib import Path
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *


def get_asn_for_ip(ip_address):
    """
    Lookup ASN information for a specific IP address.
    
    Args:
        ip_address (str): The IP address to lookup (e.g. "192.168.1.1")
        
    Returns:
        dict: ASN information dictionary with keys: asn, isp_name, network
              Returns None if no matching ASN record is found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Convert IP address to integer for comparison
        ip_int = ip_to_int(ip_address)
        if ip_int is None:
            log_error(logger, f"[ERROR] Invalid IP address format: {ip_address}")
            return None
            
        # Connect to the database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "asn")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to ASN database")
            return None
            
        cursor = conn.cursor()
        
        # Query to find the matching ASN record using run_timed_query
        query = """
            SELECT asn, isp_name, network
            FROM ipasn 
            WHERE ? BETWEEN start_ip AND end_ip 
            ORDER by netmask DESC
            LIMIT 1
        """
        rows, _ = run_timed_query(
            cursor,
            query,
            params=(ip_int,),
            description=f"get_asn_for_ip",
            fetch_all=True
        )

        if not rows:
            log_info(logger, f"[INFO] No ASN information found for IP: {ip_address}")
            return None

        row = rows[0]
        result = {
            "asn": row[0],
            "isp_name": row[1],
            "network": row[2]
        }

        log_info(logger, f"[INFO] Found ASN information for IP {ip_address}: ASN {result['asn']}, ISP: {result['isp_name']}")
        return result
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while looking up ASN for IP {ip_address}: {e}")
        return None
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while looking up ASN for IP {ip_address}: {e}")
        return None
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)
            
def ip_to_int(ip_address):
    """
    Convert an IPv4 address string to its integer representation.
    
    Args:
        ip_address (str): The IP address in dotted-decimal notation (e.g. "192.168.1.1")
        
    Returns:
        int: Integer representation of the IP address
             Returns None if the input is not a valid IPv4 address
    """
    try:
        octets = ip_address.split('.')
        if len(octets) != 4:
            return None
            
        return (int(octets[0]) << 24) + \
               (int(octets[1]) << 16) + \
               (int(octets[2]) << 8) + \
               int(octets[3])
    except (ValueError, AttributeError):
        return None

def get_all_asn_records():
    """
    Retrieve all ASN records from the database.
    
    Returns:
        list: A list of dictionaries, each containing the following keys:
              network, start_ip, end_ip, netmask, asn, isp_name.
              Returns an empty list if no records are found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "asn")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to ASN database.")
            return []
            
        cursor = conn.cursor()
        start_time = time.time()
        
        # Query to fetch all records
        cursor.execute("""
            SELECT network, start_ip, end_ip, netmask, asn, isp_name
            FROM ipasn
            ORDER BY start_ip
        """)
        
        # Fetch all rows
        rows = cursor.fetchall()
        
        # Get column names
        column_names = [description[0] for description in cursor.description]
        
        # Convert to list of dictionaries
        result = []
        for row in rows:
            result.append(dict(zip(column_names, row)))
        
        # Calculate and log total time
        total_time = time.time() - start_time
        record_count = len(result)
        log_info(logger, f"[INFO] Retrieved {record_count} ASN records in {total_time:.2f} seconds")
        
        return result
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving ASN records: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving ASN records: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def insert_asn_records_batch(records, batch_size=1000):
    """
    Insert or replace multiple ASN records in the database using batch operations.
    
    Args:
        records (list): A list of tuples, where each tuple contains:
                       (network, start_ip, end_ip, netmask, asn, isp_name)
        batch_size (int, optional): Number of records to insert in each batch. Defaults to 1000.
        
    Returns:
        tuple: (success, count) where:
               - success (bool): True if the operation was successful
               - count (int): Number of records inserted/updated
    """
    logger = logging.getLogger(__name__)
    
    if not records:
        log_warn(logger, "[WARN] No ASN records provided for batch insert")
        return True, 0
    
    try:
        # Connect to the database
        conn = connect_to_db(CONST_CONSOLIDATED_DB, "asn")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to ASN database.")
            return False, 0
            
        cursor = conn.cursor()
        start_time = time.time()
        
        # Process records in batches
        total_count = 0
        current_batch = []
        
        for record in records:
            current_batch.append(record)
            
            # When batch size is reached, insert the batch
            if len(current_batch) >= batch_size:
                cursor.executemany("""
                    INSERT OR REPLACE INTO ipasn 
                    (network, start_ip, end_ip, netmask, asn, isp_name) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, current_batch)
                conn.commit()
                total_count += len(current_batch)
                current_batch = []
                
                # Log progress for large imports
                if total_count % (batch_size * 10) == 0:
                    elapsed = time.time() - start_time
                    log_info(logger, f"[INFO] Processed {total_count} ASN records in {elapsed:.2f} seconds")
        
        # Insert any remaining records
        if current_batch:
            cursor.executemany("""
                INSERT OR REPLACE INTO ipasn 
                (network, start_ip, end_ip, netmask, asn, isp_name) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, current_batch)
            conn.commit()
            total_count += len(current_batch)
        
        # Calculate and log total time
        total_time = time.time() - start_time
        log_info(logger, f"[INFO] Successfully inserted {total_count} ASN records in {total_time:.2f} seconds")
        return True, total_count
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error during batch ASN insert: {e}")
        return False, 0
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error during batch ASN insert: {e}")
        return False, 0
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)