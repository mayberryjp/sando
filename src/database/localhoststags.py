from src.database.core import connect_to_db, disconnect_from_db


def add_tag_to_localhost(ip_address, tag):
    """
    Add a tag to the 'tags' column of a localhost entry.
    If the tag already exists, do nothing.
    """
    conn = connect_to_db("localhosts")
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT tags FROM localhosts WHERE ip_address = ?", (ip_address,)
        )
        row = cursor.fetchone()
        if row:
            tags = row[0] or ""
            tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
            if tag not in tag_list:
                tag_list.append(tag)
                new_tags = ",".join(tag_list)
                cursor.execute(
                    "UPDATE localhosts SET tags = ? WHERE ip_address = ?",
                    (new_tags, ip_address),
                )
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
    conn = connect_to_db("localhosts")
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT tags FROM localhosts WHERE ip_address = ?", (ip_address,)
        )
        row = cursor.fetchone()
        if row:
            tags = row[0] or ""
            tag_list = [t.strip() for t in tags.split(",") if t.strip()]
            if tag in tag_list:
                tag_list.remove(tag)
                new_tags = ",".join(tag_list)
                cursor.execute(
                    "UPDATE localhosts SET tags = ? WHERE ip_address = ?",
                    (new_tags, ip_address),
                )
                conn.commit()
        else:
            # Optionally, handle if the host does not exist
            pass
    finally:
        disconnect_from_db(conn)
