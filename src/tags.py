import sys
from pathlib import Path
current_dir = Path(__file__).resolve().parent
parent_dir = str(current_dir.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
src_dir = f"{parent_dir}/src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
sys.path.insert(0, "/database")
import logging


from init import *


def tag_ignorelist(record, ignorelist_entries):
    """
    Check if a single row matches any ignorelist entry.

    Args:
        row: A single flow record
        ignorelist_entries: List of ignorelist entries from database

    Returns:
        bool: True if the row matches a ignorelist entry, False otherwise
    """
    logger = logging.getLogger(__name__)
    #log_info(logger, "[INFO] Checking if the row is ignorelisted")

    if not ignorelist_entries:
        return None

   # src_ip, dst_ip, src_port, dst_port, protocol, *_ = row

    #log_info(logger, f"[INFO] Checking ignorelist for src_ip: {src_ip}, dst_ip: {dst_ip}, src_port: {src_port}, dst_port: {dst_port}, protocol: {protocol}")

    for ignorelist_id, ignorelist_src_ip, ignorelist_dst_ip, ignorelist_dst_port, ignorelist_protocol in ignorelist_entries:
        #log_info(logger, f"[INFO] Checking against ignorelist entry: {ignorelist_id}, src_ip: {ignorelist_src_ip}, dst_ip: {ignorelist_dst_ip}, dst_port: {ignorelist_dst_port}, protocol: {ignorelist_protocol}")
        # Check if the flow matches any ignorelist entry
        src_match = (ignorelist_src_ip == record['src_ip'] or ignorelist_src_ip == record['dst_ip'] or ignorelist_src_ip == "*")
        dst_match = (ignorelist_dst_ip == record['dst_ip'] or ignorelist_dst_ip == record['src_ip'] or ignorelist_dst_ip == "*")
        port_match = (ignorelist_dst_port in (record['src_port'], record['dst_port']) or ignorelist_dst_port == "*")
        protocol_match = ((int(ignorelist_protocol) == record['protocol']) or (ignorelist_protocol == "*"))

        if src_match and dst_match and port_match and protocol_match:
            #log_info(logger, f"[INFO] Row is ignorelisted with ID: {ignorelist_id}")
            return f"IgnoreList;IgnoreList_{ignorelist_id};"
    
    #log_info(logger, "[INFO] Row is not ignorelisted")
    return None

def tag_broadcast(record, broadcast_addresses):
    """
    Remove flows where the destination IP matches broadcast addresses of LOCAL_NETWORKS.
    
    Args:
        rows: List of flow records
        config_dict: Dictionary containing configuration settings
        
    Returns:
        list: Filtered rows with broadcast destination addresses removed
    """
    logger = logging.getLogger(__name__)

    if not broadcast_addresses:
        log_warn(logger, "[WARN] No broadcast addresses found for LOCAL_NETWORKS")
        return None

    if record["dst_ip"] not in broadcast_addresses:
        return None
    else:
        return "Broadcast;"
    

def tag_multicast(record):
    """
    Tag flows where the destination IP is in multicast range (224.0.0.0 to 239.255.255.255).
    
    Args:
        record: Flow record to check
        broadcast_addresses: List of broadcast addresses (not used but kept for consistency)
        
    Returns:
        str: "Multicast;" if destination IP is multicast, None otherwise
    """
    logger = logging.getLogger(__name__)

    try:
        # Get first octet of destination IP
        first_octet = int(record["dst_ip"].split('.')[0])
        
        # Check if in multicast range (224-239)
        if 224 <= first_octet <= 239:
            return "Multicast;"
        return None
        
    except (ValueError, IndexError) as e:
        log_error(logger, f"[ERROR] Invalid IP address format in record: {e}")
        return None
    
def tag_linklocal(record, link_local_range):
    """
    Tag flows where either source or destination IP is in link-local range (169.254.0.0/16).
    
    Args:
        record: Flow record to check
        
    Returns:
        str: "LinkLocal;" if either IP is in link-local range, None otherwise
    """
    logger = logging.getLogger(__name__)


    try:
        # Link-local address range
        
        # Check if source IP is in link-local range
        if is_ip_in_range(record["src_ip"], link_local_range):
            return "LinkLocal;"
            
        # Check if destination IP is in link-local range
        if is_ip_in_range(record["dst_ip"], link_local_range):
            return "LinkLocal;"
            
        return None
        
    except Exception as e:
        log_error(logger, f"[ERROR] Error checking for link-local address: {e}")
        return None

def tag_custom(record, tag_entries):
    """
    Apply custom tags to flows based on matching criteria similar to ignorelisting.
    
    Args:
        record: Flow record to check
        tag_entries: List of tag entries in format [tag_name, tag_src_ip, tag_dst_ip, tag_dst_port, tag_protocol]
        
    Returns:
        str: Custom tags to be applied or None if no matches
    """
    logger = logging.getLogger(__name__)
    
    if not tag_entries:
        return None
    
    applied_tags = []
    
    for tag_name, tag_src_ip, tag_dst_ip, tag_dst_port, tag_protocol in tag_entries:
        try:
            # Check for matches using wildcard pattern similar to ignorelist
            src_match = (tag_src_ip == record['src_ip'] or tag_src_ip == record['dst_ip'] or tag_src_ip == "*")
            dst_match = (tag_dst_ip == record['dst_ip'] or tag_dst_ip == record['src_ip'] or tag_dst_ip == "*")
            
            # Port check - handle string conversion for wildcard
            port_match = (tag_dst_port == "*" or 
                         tag_dst_port in (record['src_port'], record['dst_port']))
            
            # Protocol check - handle string conversion for wildcard
            protocol_match = (tag_protocol == "*" or 
                             int(tag_protocol) == record['protocol'])
            
            # If all criteria match, add the tag
            if src_match and dst_match and port_match and protocol_match:
                applied_tags.append(f"{tag_name};")
                #log_info(logger, f"[INFO] Custom tag '{tag_name}' applied to flow: {record['src_ip']} -> {record['dst_ip']}:{record['dst_port']}")
                
        except (ValueError, KeyError, TypeError) as e:
            log_error(logger, f"[ERROR] Error applying custom tag: {e}")
    
    # Return all matched tags as a single string
    if applied_tags:
        return "".join(applied_tags)
    return None
    
def apply_tags(record, ignorelist_entries, broadcast_addresses, tag_entries, config_dict, link_local_range):
    """
    Apply multiple tagging functions to one or more rows. For each row, append the tag to the tags position.

    Args:
        record: Flow record to tag
        ignorelist_entries: List of ignorelist entries from the database
        broadcast_addresses: Set of broadcast addresses
        tag_entries: List of custom tag entries

    Returns:
        record: Updated record with tags
    """
    # Initialize tags if not present
    if 'tags' not in record:
        record['tags'] = ""

    # Apply existing tags
    if ignorelist_entries:
        ignorelist_tag = tag_ignorelist(record, ignorelist_entries)
        if ignorelist_tag:
            record['tags'] += f"{ignorelist_tag}"

    broadcast_tag = tag_broadcast(record, broadcast_addresses)
    if broadcast_tag:
        record['tags'] += f"{broadcast_tag}"

    multicast_tag = tag_multicast(record)
    if multicast_tag:
        record['tags'] += f"{multicast_tag}"
        
    linklocal_tag = tag_linklocal(record, link_local_range)
    if linklocal_tag:
        record['tags'] += f"{linklocal_tag}"
        
    if config_dict.get("AlertOnCustomTags", 0) > 0:
        # Apply custom tags
        if tag_entries:
            custom_tags = tag_custom(record, tag_entries)
            if custom_tags:
                record['tags'] += custom_tags

    return record

