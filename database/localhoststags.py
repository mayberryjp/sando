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

def add_tag_to_localhost(ip_address, tag):
    """
    Add a tag to the 'tags' column of a localhost entry.
    If the tag already exists, do nothing.
    """
    conn = connect_to_db( "localhosts")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT tags FROM localhosts WHERE ip_address = ?", (ip_address,))
        row = cursor.fetchone()
        if row:
            tags = row[0] or ""
            tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
            if tag not in tag_list:
                tag_list.append(tag)
                new_tags = ",".join(tag_list)
                cursor.execute("UPDATE localhosts SET tags = ? WHERE ip_address = ?", (new_tags, ip_address))
                conn.commit()
        else:
            # Optionally, handle if the host does not exist
            pass
    finally:
        disconnect_from_db(conn)

def delete_tag_from_localhost(ip_address, tag):
    """
    Remove a tag from the 'tags' column of a localhost entry.
    """
    conn = connect_to_db( "localhosts")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT tags FROM localhosts WHERE ip_address = ?", (ip_address,))
        row = cursor.fetchone()
        if row:
            tags = row[0] or ""
            tag_list = [t.strip() for t in tags.split(",") if t.strip()]
            if tag in tag_list:
                tag_list.remove(tag)
                new_tags = ",".join(tag_list)
                cursor.execute("UPDATE localhosts SET tags = ? WHERE ip_address = ?", (new_tags, ip_address))
                conn.commit()
        else:
            # Optionally, handle if the host does not exist
            pass
    finally:
        disconnect_from_db(conn)