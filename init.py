# Standard library imports
import json
import logging
import os
import sqlite3
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
import importlib

# Third-party imports
import requests
import ipaddress



# Local imports - Constants
from src.const import (
    CONST_CREATE_IPASN_SQL,
    CONST_CONSOLIDATED_DB,
    CONST_TEST_SOURCE_DB,
    CONST_CREATE_ALLFLOWS_SQL,
    CONST_CREATE_ALERTS_SQL,
    CONST_CREATE_IGNORELIST_SQL,
    CONST_EXPLORE_DB,
    CONST_CREATE_CONFIG_SQL,
    CONST_CREATE_NEWFLOWS_SQL,
    CONST_CREATE_DNSKEYVALUE_SQL,
    CONST_CREATE_ACTIONS_SQL,
    CONST_CREATE_LOCALHOSTS_SQL,
    CONST_CREATE_GEOLOCATION_SQL,
    CONST_CREATE_REPUTATIONLIST_SQL,
    CONST_CREATE_EXPLORE_SQL,
    CONST_CREATE_SERVICES_SQL,
    CONST_CREATE_CUSTOMTAGS_SQL,
    CONST_PERFORMANCE_DB,
    CONST_CREATE_SERVICES_SQL,
    CONST_CREATE_TRAFFICSTATS_SQL,
    CONST_INSTALL_CONFIGS,
    CONST_CREATE_TORNODES_SQL,
    CONST_CREATE_DNSQUERIES_SQL,
    CONST_LINK_LOCAL_RANGE,
    CONST_CREATE_DBPERFORMANCE_SQL,
    CONST_SITE,
    IS_CONTAINER,
    VERSION,
    CONST_API_LISTEN_ADDRESS,
    CONST_API_LISTEN_PORT,
    CONST_DATABASE_SCHEMA_VERSION
)

from src.network import (
    is_ip_in_range,
    ip_network_to_range,
    ip_to_int,
    get_usable_ips,
    calculate_broadcast
)

# Local imports - Utilities
from src.locallogging import (
    log_info, 
    log_error, 
    log_warn,
    get_machine_unique_identifier,
    dump_json
)

from database.explore import (
    bulk_populate_master_flow_view,
     create_dns_key_value
)
# Database core functions
from database.core import (
#     connect_to_db, 
#     disconnect_from_db, 
#     create_table, 
#     delete_database,
      delete_all_records, 
    get_row_count, 
    delete_table,
    run_timed_query
)

from database.localhoststags import (
    add_tag_to_localhost,
    delete_tag_from_localhost
)

from database.common import (
    collect_database_counts,
    init_configurations_from_sitepy,
    init_configurations_from_variable, 
    store_version, 
    store_site_name,
    store_machine_unique_identifier, 
    get_machine_unique_identifier_from_db,
    update_database_schema,
    check_update_database_schema,
    test_database_online,
    get_database_metrics
)

# Alert functions
from database.alerts import (
    log_alert_to_db, 
    get_alerts_summary, 
    get_recent_alerts_by_ip, 
    get_alerts_by_category, 
    get_all_alerts,
    update_alert_acknowledgment,
    delete_alert_database,
    get_recent_alerts_database,
    get_alert_count_by_id,
    get_hourly_alerts_summary,
    summarize_alerts_by_ip,
    get_all_alerts_by_ip,
    summarize_alerts_by_ip_last_seen,
    delete_ignorelisted_alerts
)

from database.ipasn import  (
    insert_asn_records_batch,
    get_asn_for_ip
)

# Configuration functions
from database.configuration import (
    get_config_settings, 
    update_config_setting
)

from database.dnsqueries import (
    get_client_dns_queries,
    insert_dns_query,
    insert_dns_queries_batch,
    get_dnsqueries_without_responses,
    update_dns_query_response,
    get_ip_to_domain_mapping
)

# Localhost functions
from database.localhosts import (
    get_localhosts, 
    get_localhosts_all, 
    get_localhost_by_ip,
    update_localhosts, 
    insert_localhost_basic,
    classify_localhost,
    delete_localhost_database,
    update_localhost_threat_score,
    update_localhost_alerts_enabled,
    get_average_threat_score
)

from database.allflows import (
    update_all_flows,
    update_tag_to_allflows,
    get_flows_by_source_ip,
    get_dead_connections_from_database,
    get_tag_statistics,
    apply_ignorelist_entry
)

# Traffic Stats functions
from database.trafficstats import (
    update_traffic_stats, 
    delete_old_traffic_stats,
    get_traffic_stats_for_ip
)

# Ignore List and Tag functions
from database.ignorelist import (
    get_ignorelist, 
    import_ignorelists,
    delete_ignorelist_entry,
    insert_ignorelist_entry,
    get_ignorelist_for_ip,
    whitelist_approved_ntp_servers,
    whitelist_approved_dns_servers
)

from database.customtags import (
    get_custom_tags, 
    import_custom_tags,
    insert_custom_tag
)

# Action functions
from database.actions import (
    update_action_acknowledged, 
    insert_action, 
    get_all_actions,
    update_action_acknowledged_all
)

# Service functions
from database.services import (
    get_services_by_port, 
    get_all_services_database,
    insert_service,
    insert_services_bulk
)

from database.tornodes import (
    get_all_tor_nodes,
    insert_tor_node
)

from database.newflows import (
    update_new_flow
)