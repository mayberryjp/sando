import dns.resolver
import logging
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


def resolve_empty_dns_responses(config_dict):
    """
    Retrieve DNS queries with no responses, perform DNS lookups on them,
    and update the dnsqueries table with the results.
    
    Args:
        dns_servers (list): DNS servers to use for lookups. If None, uses config settings.
        config_dict (dict): Configuration dictionary.
        batch_size (int): Number of queries to process in each batch.
        
    Returns:
        dict: Statistics about the resolution process.
    """
    logger = logging.getLogger(__name__)
    log_info(logger, "[INFO] Starting DNS resolution for queries with empty responses")
    
    # Initialize stats
    stats = {
        "processed": 0,
        "successful": 0,
        "failed": 0
    }
    
    try:
        dns_servers_str = config_dict.get('DnsResponseLookupResolver', None)
        dns_servers = dns_servers_str.split(',')
        
        # Get queries with empty responses
        empty_queries = get_dnsqueries_without_responses()
        
        if not empty_queries:
            log_info(logger, "[INFO] No DNS queries with empty responses found")
            return stats
            
        log_info(logger, f"[INFO] Found {len(empty_queries)} DNS queries with empty responses")
        
        # Create DNS resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = dns_servers
        resolver.timeout = config_dict.get('DnsResolverTimeout', 3)
        resolver.lifetime = config_dict.get('DnsResolverRetries', 1)
        
        # Process each query and update the database
        for query in empty_queries:
            query_id = query[0]
            domain = query[1]
            query_type = query[2]  # Default to A record if not specified
            
            try:
                # Perform forward DNS lookup
                #log_info(logger, f"[INFO] Resolving {domain} ({query_type})")
                answers = resolver.resolve(domain, query_type)
                
                # Format the response
                response_data = []
                for answer in answers:
                    response_data.append(str(answer))
                
                # Join multiple answers with comma
                response = ','.join(response_data)
                
                # Update the database
                success = update_dns_query_response(response, query_id)
                
                if success:
                    #log_info(logger, f"[INFO] Updated response for {domain} ({query_type}): {response}")
                    stats["successful"] += 1
                else:
                    log_warn(logger, f"[WARN] Failed to update response for {domain} ({query_type})")
                    stats["failed"] += 1
                    
            except dns.resolver.NXDOMAIN:
                # Update with NXDOMAIN response
                update_dns_query_response("NXDOMAIN", query_id)
                log_info(logger, f"[INFO] Domain {domain} not found (NXDOMAIN)")
                stats["successful"] += 1
                
            except dns.resolver.Timeout:
                update_dns_query_response("TIMEOUT", query_id)
                log_warn(logger, f"[WARN] Timeout resolving {domain}")
                stats["successful"] += 1
                
            except dns.resolver.NoAnswer:
                update_dns_query_response("NOANSWER", query_id)
                log_warn(logger, f"[WARN] No answer for {domain} ({query_type})")
                stats["successful"] += 1
                
            except dns.resolver.NoNameservers:
                update_dns_query_response("NONAMESERVERS", query_id)
                log_warn(logger, f"[WARN] No nameservers for {domain}")
                stats["successful"] += 1
                
            except Exception as e:
                update_dns_query_response(f"ERROR: {str(e)[:100]}", query_id)
                log_error(logger, f"[ERROR] Failed to resolve {domain}: {e}")
                stats["failed"] += 1
                
            stats["processed"] += 1
            
        log_info(logger, f"[INFO] DNS resolution complete. Processed: {stats['processed']}, "
                         f"Successful: {stats['successful']}, Failed: {stats['failed']}")
        
        return stats
        
    except Exception as e:
        log_error(logger, f"[ERROR] Error in DNS resolution process: {e}")
        return stats


def dns_lookup(ip_addresses, dns_servers, config_dict):
    """
    Perform DNS lookup for a list of IP addresses using specific DNS servers.

    Args:
        ip_addresses (list): A list of IP addresses to perform DNS lookups on.
        dns_servers (list): A list of DNS servers to use for lookups (default is ['8.8.8.8']).

    Returns:
        dict: A dictionary where the keys are IP addresses and the values are the resolved hostnames or an error message.
    """
    logger = logging.getLogger(__name__)

    resolver_timeout = config_dict['DnsResolverTimeout'] if 'DnsResolverTimeout' in config_dict else 3
    resolver_retries = config_dict['DnsResolverRetries'] if 'DnsResolverRetries' in config_dict else 1
    
    log_info(logger,f"[INFO] DNS discovery starting")
    results = []
    resolver = dns.resolver.Resolver()
    log_info(logger,f"[INFO] DNS servers are {dns_servers}")
    resolver.nameservers = dns_servers  # Set the specific DNS servers
    resolver.timeout = resolver_timeout
    resolver.lifetime = resolver_retries

    count = 0
    total = len(ip_addresses)

    for ip in ip_addresses:

        try:
            # Perform reverse DNS lookup
            query = resolver.resolve_address(ip)
            hostname = str(query[0])  # Extract the hostname
            results.append({
                "ip": ip,
                "dns_hostname": hostname
            })

        except dns.resolver.NXDOMAIN:
            results.append({
                "ip": ip,
                "dns_hostname": "NXDOMAIN"
            })
            insert_action(f"You have an IP address without a reverse DNS entry. It is recommeneded to inventory all your local network devices in your local DNS. In Pi-hole, you can do this by going to Settings > Local DNS Records. Affected IP address is {ip}. DNS response was 'NXDOMAIN'.")
        except dns.resolver.Timeout:
            results.append({
                "ip": ip,
                "dns_hostname": "TIMEOUT"
            })
        except dns.resolver.NoNameservers:
            results.append({
                "ip": ip,
                "dns_hostname": "NONAMESERVER"
            })
        except Exception as e:
            results.append({
                "ip": ip,
                "dns_hostname": "ERROR"
            })

    log_info(logger,f"[INFO] DNS discovery finished")
    return results
