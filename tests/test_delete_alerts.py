import sys
import os
from pathlib import Path
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
from datetime import datetime
from init import *

# Set up path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

# Import the function to test and database utilities
from database.alerts import delete_ignorelisted_alerts
from database.core import connect_to_db, disconnect_from_db
from locallogging import log_info, log_error

def setup_test_data(conn):
    """Set up test alert data in the database"""
    cursor = conn.cursor()
    
    # Clear existing alerts
    cursor.execute("DELETE FROM alerts")
    
    # Insert test alerts with various IP, port, and protocol combinations
    test_alerts = [
        {
            'id': 'test1',
            'ip_address': '192.168.1.100',
            'flow': json.dumps({
                'src_ip': '192.168.1.100', 
                'dst_ip': '10.0.0.1', 
                'src_port': 45000, 
                'dst_port': 80, 
                'protocol': '6'
            }),
            'category': 'test'
        },
        {
            'id': 'test2',
            'ip_address': '192.168.1.200',
            'flow': json.dumps({
                'src_ip': '192.168.1.200', 
                'dst_ip': '8.8.8.8', 
                'src_port': 55000, 
                'dst_port': 53, 
                'protocol': '17'
            }),
            'category': 'test'
        },
        {
            'id': 'test3',
            'ip_address': '10.0.0.50',
            'flow': json.dumps({
                'src_ip': '10.0.0.50', 
                'dst_ip': '192.168.1.100', 
                'src_port': 33000, 
                'dst_port': 22, 
                'protocol': '6'
            }),
            'category': 'test'
        },
        {
            'id': 'test4',
            'ip_address': '10.0.0.51',
            'flow': json.dumps({
                'src_ip': '10.0.0.51', 
                'dst_ip': '8.8.8.8', 
                'src_port': 45678, 
                'dst_port': 53, 
                'protocol': '17'
            }),
            'category': 'test'
        },
        {
            'id': 'test5',
            'ip_address': '192.168.1.150',
            'flow': json.dumps({
                'src_ip': '192.168.1.150', 
                'dst_ip': '10.0.0.5', 
                'src_port': 44444, 
                'dst_port': 443, 
                'protocol': '6' 
            }),
            'category': 'test'
        }
    ]
    
    # Insert test alerts
    for alert in test_alerts:
        cursor.execute("""
            INSERT INTO alerts (id, ip_address, flow, category, alert_enrichment_1, alert_enrichment_2, times_seen, first_seen, last_seen, acknowledged)
            VALUES (?, ?, ?, ?, '', '', 1, datetime('now', 'localtime'), datetime('now', 'localtime'), 0)
        """, (alert['id'], alert['ip_address'], alert['flow'], alert['category']))
    
    conn.commit()
    
    # Verify data insertion
    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]
    return count

def count_alerts(conn):
    """Count remaining alerts in the database"""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    return cursor.fetchone()[0]

def run_test():
    """Run tests for delete_ignorelisted_alerts function"""
    # Set up logging
    logger = logging.getLogger(__name__)
    
    print(f"=== Testing delete_ignorelisted_alerts function ===")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    try:
        # Connect to the database
        conn = connect_to_db( "alerts")
        if not conn:
            print("ERROR: Unable to connect to the database")
            return
        
        # Set up test data
        initial_count = setup_test_data(conn)
        print(f"Test data setup complete. Inserted {initial_count} test alerts.")
        
        # Define test cases
        test_cases = [
            {
                'name': "Match specific source IP",
                'params': {
                    'ignorelist_id': 'test_ignore_1',
                    'src_ip': '192.168.1.100',
                    'dst_ip': '*',
                    'dst_port': '*',
                    'protocol': '*'
                },
                'expected_deleted': 1
            },
            {
                'name': "Match specific destination IP",
                'params': {
                    'ignorelist_id': 'test_ignore_2',
                    'src_ip': '*',
                    'dst_ip': '8.8.8.8',
                    'dst_port': '*',
                    'protocol': '*'
                },
                'expected_deleted': 2
            },
            {
                'name': "Match specific port",
                'params': {
                    'ignorelist_id': 'test_ignore_3',
                    'src_ip': '*',
                    'dst_ip': '*',
                    'dst_port': '53',
                    'protocol': '*'
                },
                'expected_deleted': 2
            },
            {
                'name': "Match source IP and protocol",
                'params': {
                    'ignorelist_id': 'test_ignore_4',
                    'src_ip': '10.0.0.51',
                    'dst_ip': '*',
                    'dst_port': '*',
                    'protocol': '17'
                },
                'expected_deleted': 1
            },
            {
                'name': "Match all parameters",
                'params': {
                    'ignorelist_id': 'test_ignore_5',
                    'src_ip': '192.168.1.150',
                    'dst_ip': '10.0.0.5',
                    'dst_port': '443',
                    'protocol': '6'
                },
                'expected_deleted': 1
            },
            {
                'name': "No matches",
                'params': {
                    'ignorelist_id': 'test_ignore_6',
                    'src_ip': '1.1.1.1',
                    'dst_ip': '2.2.2.2',
                    'dst_port': '1234',
                    'protocol': '1'
                },
                'expected_deleted': 0
            }
        ]
        
        # Run test cases
        for i, test in enumerate(test_cases):
            # Reset test data before each test
            setup_test_data(conn)
            
            print(f"\nTest {i+1}: {test['name']}")
            print(f"Parameters: {test['params']}")
            
            # Execute the function
            deleted = delete_ignorelisted_alerts(**test['params'])
            
            # Check results
            remaining = count_alerts(conn)
            success = deleted == test['expected_deleted']
            
            print(f"Deleted: {deleted}, Expected: {test['expected_deleted']}")
            print(f"Remaining alerts: {remaining}")
            print(f"Result: {'✅ PASS' if success else '❌ FAIL'}")
        
        print("\n" + "="*60)
        print("All tests completed.")
        
    except Exception as e:
        print(f"ERROR: Test failed with exception: {e}")
    finally:
        # Clean up
        if 'conn' in locals() and conn:
            try:
                # Clean up test data
                cursor = conn.cursor()
                cursor.execute("DELETE FROM alerts WHERE category='test'")
                conn.commit()
            except:
                pass
            disconnect_from_db(conn)

if __name__ == "__main__":
    run_test()