import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
# Set up path for imports
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

sys.path.insert(0, "/database")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from init import *
# Add parent directory to path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database.dnsqueries import get_ip_to_domain_mapping

def main():
    print("Starting IP to Domain mapping test...")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 80)
    
    try:
        # Call the function
        start_time = datetime.now()
        ip_domain_map = get_ip_to_domain_mapping()
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Print statistics
        print(f"Total IP-domain mappings found: {len(ip_domain_map)}")
        print(f"Execution time: {execution_time:.2f} seconds")
        print("-" * 80)
        
        # Print the first 10 mappings as a sample
        print("Sample of mappings (first 10):")
        for i, (ip, domain) in enumerate(list(ip_domain_map.items())[:10]):
            print(f"{i+1}. {ip} -> {domain}")
            
        # Option to save full results to a file
        save_option = input("\nDo you want to save the full mapping to a JSON file? (y/n): ")
        if save_option.lower() == 'y':
            filename = f"ip_domain_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(ip_domain_map, f, indent=2)
            print(f"Results saved to {filename}")
        
    except Exception as e:
        print(f"Error executing IP to domain mapping: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())