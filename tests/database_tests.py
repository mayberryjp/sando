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

def run_and_dump_database_metrics():
    """
    Executes get_database_metrics and prints the output as formatted JSON.
    """
    logging.basicConfig(level=logging.INFO)
    #metrics = get_database_metrics()
  #  print(json.dumps(metrics, indent=2, sort_keys=True))

if __name__ == "__main__":
    run_and_dump_database_metrics()