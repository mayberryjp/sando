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
import csv
import io



def get_services_by_port(port_number):
    """
    Retrieve service information for a specific port number.
    
    Args:
        port_number (int): The port number to query
        
    Returns:
        dict: A dictionary where keys are protocols (e.g., 'tcp', 'udp') and values 
              are dictionaries containing 'service_name' and 'description'.
              Returns an empty dictionary if no services found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the services database
        conn = connect_to_db( "services")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to services database.")
            return {}
            
        cursor = conn.cursor()
        
        # Query services for the specified port
        cursor.execute("""
            SELECT protocol, service_name, description 
            FROM services 
            WHERE port_number = ?
        """, (port_number,))
        
        rows = cursor.fetchall()
        
        # Format results as a dictionary
        services_dict = {}
        for row in rows:
            protocol = row[0]
            services_dict[protocol] = {
                'service_name': row[1],
                'description': row[2]
            }
        
        log_info(logger, f"[INFO] Retrieved {len(services_dict)} service entries for port {port_number}.")
        return services_dict
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving services for port {port_number}: {e}")
        return {}
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving services for port {port_number}: {e}")
        return {}
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def get_all_services_database():
    """
    Retrieve all service information from the services table.
    
    Returns:
        list: A list of dictionaries containing service information with keys:
              'port_number', 'protocol', 'service_name', 'description'.
              Returns an empty list if no services found or an error occurs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the services database
        conn = connect_to_db( "services")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to services database.")
            return []
            
        cursor = conn.cursor()
        
        # Query all services
        cursor.execute("""
            SELECT port_number, protocol, service_name, description 
            FROM services 
            ORDER BY port_number, protocol
        """)
        
        rows = cursor.fetchall()
        
        log_info(logger, f"[INFO] Retrieved {len(rows)} service entries from the database.")
        return rows
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while retrieving services: {e}")
        return []
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while retrieving services: {e}")
        return []
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)
    
def insert_service(port_number, protocol, service_name, description):
    """
    Insert or replace a service record in the services table.
    
    Args:
        port_number (int): The port number of the service
        protocol (str): The protocol (e.g., 'tcp', 'udp')
        service_name (str): The name of the service
        description (str): A description of the service
        
    Returns:
        bool: True if the insertion/update was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Connect to the services database
        conn = connect_to_db( "services")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to services database.")
            return False
            
        cursor = conn.cursor()
        
        # Insert or replace the service record
        cursor.execute("""
            INSERT OR REPLACE INTO services 
            (port_number, protocol, service_name, description) 
            VALUES (?, ?, ?, ?)
        """, (port_number, protocol, service_name, description))
        
        # Commit the changes
        conn.commit()
        
        #log_info(logger, f"[INFO] Successfully inserted/updated service record for port {port_number}/{protocol}: {service_name}")
        return True
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while inserting service record: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error while inserting service record: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def insert_services_bulk(service_records):
    """
    Insert or replace multiple service records in the services table in a single batch operation.
    
    Args:
        service_records (list): A list of tuples, where each tuple contains:
                               (port_number, protocol, service_name, description)
        
    Returns:
        tuple: (success, count) where:
               - success (bool): True if the operation was successful
               - count (int): Number of records inserted/updated
    """
    logger = logging.getLogger(__name__)
    
    if not service_records:
        log_warn(logger, "[WARN] No service records provided for bulk insert")
        return True, 0
    
    try:
        # Connect to the services database
        conn = connect_to_db( "services")
        if not conn:
            log_error(logger, "[ERROR] Unable to connect to services database.")
            return False, 0
            
        cursor = conn.cursor()
        
        # Start time measurement
        start_time = time.time()
        
        # Batch insert or replace the service records
        cursor.executemany("""
            INSERT OR REPLACE INTO services 
            (port_number, protocol, service_name, description) 
            VALUES (?, ?, ?, ?)
        """, service_records)
        
        # Commit the changes
        conn.commit()
        
        # Calculate execution time
        execution_time = (time.time() - start_time) * 1000
        record_count = len(service_records)
        
        log_info(logger, f"[INFO] Successfully bulk inserted/updated {record_count} service records in {execution_time:.2f} ms")
        return True, record_count
        
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error during bulk service insert: {e}")
        return False, 0
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error during bulk service insert: {e}")
        return False, 0
    finally:
        if 'conn' in locals() and conn:
            disconnect_from_db(conn)

def create_services_db():
    """
    Downloads the IANA service names and port numbers CSV and stores it in the database
    using efficient bulk inserts.
    
    The function creates a 'services' table with columns:
    - port_number (integer)
    - protocol (string)
    - service_name (string)
    - description (string)
    """
    logger = logging.getLogger(__name__)
    
    # IANA services CSV URL
    csv_url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
    
    try:
        # Step 1: Download the CSV file
        log_info(logger, "[INFO] Downloading IANA service names and port numbers CSV...")
        response = requests.get(csv_url, timeout=30)
        
        if response.status_code != 200:
            log_error(logger, f"[ERROR] Failed to download IANA services CSV: {response.status_code}")
            return False
        
        # Step 2: Parse and insert the CSV data
        log_info(logger, "[INFO] Parsing and preparing IANA services data...")
        
        delete_all_records( "services")
        
        # Parse CSV
        csv_data = io.StringIO(response.text)
        reader = csv.DictReader(csv_data)
        
        # Collect records for bulk insert
        batch_size = 1000
        service_records = []
        total_count = 0
        batch_count = 0
        
        for row in reader:
            service_name = row.get("Service Name", "")
            port_number = row.get("Port Number", "")
            protocol = row.get("Transport Protocol", "")
            description = row.get("Description", "")
            
            # Skip rows without a port number or where port is a range
            if not port_number or "-" in port_number:
                continue
                
            try:
                # Convert port to integer
                port_int = int(port_number)
                
                # Add to batch
                service_records.append((port_int, protocol, service_name, description))
                batch_count += 1
                
                # Insert in batches to avoid large transactions
                if batch_count >= batch_size:
                    success, count = insert_services_bulk(service_records)
                    if success:
                        total_count += count
                        log_info(logger, f"[INFO] Processed batch of {count} service entries (total: {total_count})...")
                    else:
                        log_error(logger, f"[ERROR] Failed to insert batch of {len(service_records)} records")
                    
                    # Reset batch
                    service_records = []
                    batch_count = 0
                    
            except ValueError:
                # Skip rows where port cannot be converted to integer
                continue
        
        # Insert any remaining records
        if service_records:
            success, count = insert_services_bulk(service_records)
            if success:
                total_count += count
            else:
                log_error(logger, f"[ERROR] Failed to insert final batch of {len(service_records)} records")
        
        log_info(logger, f"[INFO] Successfully loaded {total_count} IANA service entries into the database.")
        return True
        
    except requests.RequestException as e:
        log_error(logger, f"[ERROR] Error downloading IANA services CSV: {e}")
        return False
    except sqlite3.Error as e:
        log_error(logger, f"[ERROR] Database error while creating services database: {e}")
        return False
    except Exception as e:
        log_error(logger, f"[ERROR] Unexpected error creating services database: {e}")
        return False