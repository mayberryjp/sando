VERSION="v0.3.1077"
# v3 is after consolidating database, v4 is moving to ORM, v5 is moving to constructor, v6 is integrating agent
CONST_COLLECTOR_LISTEN_PORT=2055
CONST_COLLECTOR_LISTEN_ADDRESS="0.0.0.0"
CONST_API_LISTEN_PORT=8044
CONST_API_LISTEN_ADDRESS="0.0.0.0"
IS_CONTAINER=1

CONST_CONFIGURATION_DB = "/database/configuration.db"
CONST_PERFORMANCE_DB= "/database/performance.db"
CONST_EXPLORE_DB= "/database/explore.db"
CONST_LOCALHOSTS_DB="/database/localhosts.db"
CONST_ACTIONS_DB="/database/actions.db"
CONST_ALERTS_DB="/database/alerts.db"
CONST_ALLFLOWS_DB="/database/allflows.db"
CONST_CUSTOMTAGS_DB="/database/customtags.db"
CONST_DNSQUERIES_DB="/database/dnsqueries.db"
CONST_GEOLOCATION_DB="/database/geolocation.db"
CONST_IGNORELIST_DB="/database/ignorelist.db"
CONST_IPASN_DB="/database/ipasn.db"
CONST_NEWFLOWS_DB="/database/newflows.db"
CONST_REPUTATIONLIST_DB="/database/reputationlist.db"
CONST_SERVICES_DB="/database/services.db"
CONST_TORNODES_DB="/database/tornodes.db"
CONST_TRAFFICSTATS_DB="/database/trafficstats.db"
#CONST_TEST_SOURCE_DB = ['/database/test_source_1.db','/database/test_source_2.db']
TABLE_DB_MAP = {
    "localhosts": CONST_LOCALHOSTS_DB,
    "alerts": CONST_ALERTS_DB,
    "actions": CONST_ACTIONS_DB,
    "trafficstats": CONST_TRAFFICSTATS_DB,
    "configuration": CONST_CONFIGURATION_DB,
    "allflows": CONST_ALLFLOWS_DB,
    "customtags": CONST_CUSTOMTAGS_DB,
    "dnsqueries": CONST_DNSQUERIES_DB,
    "explore": CONST_EXPLORE_DB,
    "geolocation": CONST_GEOLOCATION_DB,
    "ignorelist": CONST_IGNORELIST_DB,
    "asn": CONST_IPASN_DB,
    "ipasn": CONST_IPASN_DB,
    "newflows": CONST_NEWFLOWS_DB,
    "reputationlist": CONST_REPUTATIONLIST_DB,
    "services": CONST_SERVICES_DB,
    "tornodes": CONST_TORNODES_DB,
    "dbperformance": CONST_PERFORMANCE_DB,
    "dnskeyvalue": CONST_EXPLORE_DB,
    # Add other mappings as needed
}
CONST_TEST_SOURCE_DB = ['/database/test_source_1.db']
CONST_SITE= 'TESTPPE'
CONST_LINK_LOCAL_RANGE = ["169.254.0.0/16"]
CONST_REINITIALIZE_DB = 0
CONST_DATABASE_SCHEMA_VERSION=15
CONST_CREATE_DBPERFORMANCE_SQL='''
            CREATE TABLE IF NOT EXISTS dbperformance (
                id INTEGER PRIMARY KEY,
                db_name TEXT NOT NULL,
                query TEXT,
                function TEXT,
                execution_time REAL,
                rows_returned INTEGER,
                run_timestamp TEXT
            )'''
CONST_CREATE_DNSKEYVALUE_SQL='''
            CREATE TABLE IF NOT EXISTS dnskeyvalue (
                ip TEXT PRIMARY KEY,
                domain TEXT
            )'''
CONST_CREATE_EXPLORE_SQL='''
            CREATE TABLE IF NOT EXISTS explore (
                flow_id INTEGER PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                src_ip_int INTEGER,
                dst_ip_int INTEGER,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                tags TEXT,
                flow_start TEXT,
                last_seen TEXT,
                packets INTEGER,
                bytes INTEGER,
                times_seen INTEGER,
                src_dns TEXT,
                dst_dns TEXT,
                src_country TEXT,
                dst_country TEXT,
                src_asn TEXT,
                dst_asn TEXT,
                src_isp TEXT,
                dst_isp TEXT,
                concat TEXT
            )'''
CONST_CREATE_NEWFLOWS_SQL='''
    CREATE TABLE IF NOT EXISTS newflows (
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol INTEGER,
        packets INTEGER,
        bytes INTEGER,
        flow_start TEXT,
        flow_end TEXT,
        last_seen TEXT,
        times_seen INTEGER,
        tags TEXT,
        PRIMARY KEY (src_ip, dst_ip, src_port, dst_port, protocol)
    )'''

CONST_CREATE_SERVICES_SQL="""
    CREATE TABLE IF NOT EXISTS services (
        port_number INTEGER,
        protocol TEXT,
        service_name TEXT,
        description TEXT,
        PRIMARY KEY (port_number, protocol)
    )"""

CONST_CREATE_ALLFLOWS_SQL='''
    CREATE TABLE IF NOT EXISTS allflows (
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol INTEGER,
        packets INTEGER,
        bytes INTEGER,
        flow_start TEXT,
        flow_end TEXT,
        times_seen INTEGER DEFAULT 1,
        last_seen TEXT,
        tags TEXT,
        PRIMARY KEY (src_ip, dst_ip, src_port, dst_port, protocol)
    );

    CREATE INDEX IF NOT EXISTS idx_allflows_src_ip_tags ON allflows(src_ip);

    CREATE INDEX IF NOT EXISTS idx_allflows_dst_ip_tags ON allflows(dst_ip);

    CREATE INDEX IF NOT EXISTS idx_allflows_flow_dates ON allflows(flow_start, last_seen);   
    '''

CONST_CREATE_ALERTS_SQL='''
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,  -- Primary key based on concatenating ip_address and category
        ip_address TEXT,
        flow TEXT,
        category TEXT,
        alert_enrichment_1 TEXT,
        alert_enrichment_2 TEXT,
        times_seen INTEGER DEFAULT 0,
        first_seen TEXT,
        last_seen TEXT,
        acknowledged INTEGER DEFAULT 0
    );
    
    CREATE INDEX IF NOT EXISTS idx_alerts_ip_address ON alerts(ip_address);
'''

CONST_CREATE_IGNORELIST_SQL='''
    CREATE TABLE IF NOT EXISTS ignorelist (
        ignorelist_id TEXT PRIMARY KEY,
        ignorelist_src_ip TEXT,
        ignorelist_dst_ip TEXT,
        ignorelist_dst_port INTEGER,
        ignorelist_protocol INTEGER,
        ignorelist_insert_date TEXT,
        ignorelist_enabled INTEGER DEFAULT 1,
        ignorelist_description TEXT,
        ignorelist_added TEXT
    )'''

CONST_CREATE_CUSTOMTAGS_SQL='''
    CREATE TABLE IF NOT EXISTS customtags (
        tag_id TEXT PRIMARY KEY,
        src_ip TEXT,
        dst_ip TEXT,
        dst_port INTEGER,
        protocol TEXT,
        tag_name TEXT,
        enabled INTEGER DEFAULT 1,
        added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        insert_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )'''

CONST_CREATE_CONFIG_SQL='''
    CREATE TABLE IF NOT EXISTS configuration (
        key TEXT PRIMARY KEY,
        value INT,
        last_changed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )'''

CONST_CREATE_GEOLOCATION_SQL="""
    CREATE TABLE IF NOT EXISTS geolocation (
        network TEXT PRIMARY KEY,
        start_ip INTEGER,
        end_ip INTEGER,
        netmask INTEGER,
        country_name TEXT
    )"""

CONST_CREATE_LOCALHOSTS_SQL = """
    CREATE TABLE IF NOT EXISTS localhosts (
        ip_address TEXT PRIMARY KEY,
        first_seen TEXT,
        original_flow TEXT,
        mac_address TEXT,
        mac_vendor TEXT,
        dhcp_hostname TEXT,
        dns_hostname TEXT,
        os_fingerprint TEXT,
        local_description TEXT,
        lease_hostname TEXT,
        lease_hwaddr TEXT,
        lease_clientid TEXT,
        icon TEXT,                -- New column for icon
        tags TEXT,                -- New column for tags
        acknowledged INTEGER DEFAULT 0,
        threat_score INTEGER DEFAULT 1, -- New column for threat score
        alerts_enabled INTEGER DEFAULT 1,
        management_link TEXT,
        last_seen TEXT,
        last_dhcp_discover TEXT
    )
"""

CONST_CREATE_IPASN_SQL="""
        CREATE TABLE IF NOT EXISTS ipasn (
            network TEXT PRIMARY KEY,
            start_ip INTEGER,
            end_ip INTEGER,
            netmask INTEGER,
            asn TEXT,
            isp_name TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_ipasn_ip_range ON ipasn (start_ip, end_ip);
    """

CONST_CREATE_TRAFFICSTATS_SQL = """
    CREATE TABLE IF NOT EXISTS trafficstats (
        ip_address TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        total_packets INTEGER DEFAULT 0,
        total_bytes INTEGER DEFAULT 0,
        PRIMARY KEY (ip_address, timestamp)
    );
    
    CREATE INDEX IF NOT EXISTS idx_trafficstats_ip_address ON trafficstats(ip_address);"""

CONST_CREATE_REPUTATIONLIST_SQL="""
    CREATE TABLE IF NOT EXISTS reputationlist (
        network TEXT PRIMARY KEY,
        start_ip INTEGER,
        end_ip INTEGER,
        netmask INTEGER
    )
"""

CONST_CREATE_TORNODES_SQL = '''
    CREATE TABLE IF NOT EXISTS tornodes (
        ip_address TEXT PRIMARY KEY,
        import_date TEXT
    )
'''

CONST_CREATE_DNSQUERIES_SQL = '''
CREATE TABLE IF NOT EXISTS dnsqueries (
    id INTEGER,
    client_ip TEXT NOT NULL,
    times_seen INTEGER DEFAULT 0,
    last_seen TEXT,
    first_seen TEXT,
    type TEXT NOT NULL,
    domain TEXT NOT NULL,
    response TEXT,
    datasource TEXT NOT NULL,
    last_refresh TEXT,
    PRIMARY KEY (client_ip, domain, type, datasource),
    UNIQUE (id)
);

CREATE TRIGGER IF NOT EXISTS auto_increment_dnsqueries_id
AFTER INSERT ON dnsqueries
BEGIN
    UPDATE dnsqueries 
    SET id = (SELECT COALESCE(MAX(id), 0) + 1 FROM dnsqueries)
    WHERE rowid = NEW.rowid AND id IS NULL;
END;
'''

CONST_CREATE_ACTIONS_SQL = '''
    CREATE TABLE IF NOT EXISTS actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_text TEXT,
    acknowledged INTEGER DEFAULT 0,
    insert_date TEXT DEFAULT (datetime('now', 'localtime'))
    )
'''

CONST_INSTALL_CONFIGS = [
    ('NewHostsDetection', 1),
    ('LocalFlowsDetection', 0),
    ('RouterFlowsDetection', 0),
    ('ForeignFlowsDetection', 0),
    ('NewOutboundDetection', 0),
    ('GeolocationFlowsDetection', 0),
    ('BypassLocalDnsDetection', 0),
    ('IncorrectAuthoritativeDnsDetection', 0),
    ('BypassLocalNtpDetection', 0),
    ('IncorrectNtpStratrumDetection', 0),
    ('ApprovedLocalNtpServersList',''),
    ('ApprovedLocalDnsServersList',''),
    ('ApprovedAuthoritativeDnsServersList',''),
    ('ApprovedNtpStratumServersList',''),
    ('BannedCountryList','North Korea,Iran,Russia,Ukraine,Georgia,Armenia,Azerbaijan,Belarus,Syria,Venezuela,Cuba,Myanmar,Afghanistan'),
    ('LocalNetworks',''),
    ('ProcessingInterval','60'),
    ('TelegramBotToken',''),
    ('TelegramChatId',''),
    ('ScheduleProcessor','1'),
    ('StartCollector','1'),
    ('CleanNewFlows','1'),
    ('DeadConnectionDetection','0'),
    ('IgnoreListEntries', ''),
    ('DnsResolverTimeout', 3),
    ('DnsResolverRetries', 1),
    ('PiholeUrl', 'http://192.168.49.80/api'),
    ('PiholeApiKey',''),
    ('DiscoveryReverseDns', '0'),
    ('DiscoveryPiholeDhcp', '0'),
    ('EnableLocalDiscoveryProcess', '0'),
    ('DiscoveryProcessRunInterval', '28800'),
    ('DiscoveryNmapOsFingerprint',0),
    ('ReputationUrl','https://iplists.firehol.org/files/firehol_level1.netset'),
    ('ReputationListRemove','192.168.0.0/16,0.0.0.0/8,224.0.0.0/3,169.254.0.0/16'),
    ('ReputationListDetection','0'),
    ('VpnTrafficDetection','0'),
    ('ApprovedVpnServersList',''),
    ('RemoveBroadcastFlows',1),
    ('HighRiskPortDetection','0'),
    ('HighRiskPorts','135,137,138,139,445,25,587,22,23,3389'),
    ('MaxUniqueDestinations','30'),
    ('ManyDestinationsDetection','0'),
    ('MaxPortsPerDestination','15'),
    ('PortScanDetection','0'),
    ('IntegrationFetchInterval',86400),
    ('TorFlowDetection','0'),
    ('TorNodesUrl','https://www.dan.me.uk/torlist/?full'),
    ('HighBandwidthFlowDetection','0'),
    ('MaxPackets',30000),
    ('MaxBytes',3000000),
    ('StorePiHoleDnsQueryHistory','0'),
    ('SendDeviceClassificationsToHomelabApi','0'),
    ('CollectorProcessingInterval','60'),
    ('SendErrorsToCloudApi','0'),
    ('RemoveMulticastFlows','1'),
    ('TagEntries', '[]'), 
    ('AlertOnCustomTagList',''),  
    ('AlertOnCustomTags','0'), 
    ('SendConfigurationToCloudApi','0'),
    ('ApprovedHighRiskDestinations', ''), 
    ('IgnoreListEntries', '[]'),
    ('MaxMindAPIKey', ''),  
    ('RemoveLinkLocalFlows', '1'),
    ('ImportServicesList','1'),
    ('TelegramEnabled', '0'),
    ('ImportAsnDatabase', '1'),
    ('PiHoleDnsFetchRecordSize', '10000'),
    ('PiHoleDnsFetchInterval', '3600'),
    ('TrafficStatsPurgeIntervalDays','31'),
    ('SinkHoleDns', '0'),
    ('DhcpServer', '0'),
    ('DnsResponseLookupResolver',''),
    ('PerformDnsResponseLookupsForInvestigations','0'),
    ('ProcessRunInterval','60'),
    ('IntegrationFetchInterval','86400'),
    ('DatabaseSchemaVersion', '13'),
]