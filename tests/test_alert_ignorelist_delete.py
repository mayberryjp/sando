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

from init import *

if __name__ == "__main__":
    # Example variables - replace these with your own values for testing
    ignorelist_id = "LocalServerExposed-1"
    src_ip = "*"
    dst_ip = "192.168.60.4"
    dst_port = "8045"
    protocol = "6"

    # Call the function with your test variables
    result = delete_ignorelisted_alerts(ignorelist_id, src_ip, dst_ip, dst_port, protocol)
    print("delete_ignorelisted_alerts result:", result)