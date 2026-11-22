import configparser
import ipaddress
import json
import multiprocessing
import os
import socket
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from bottle import Bottle

from src import const
from src.database.configuration import get_config_settings, update_flow_metrics
from src.database.explore import bulk_populate_master_flow_view, get_flows_for_ip
from src.database.geolocation import get_all_geolocations, get_country_by_ip_int, insert_geolocation
from src.database.ipasn import get_asn_for_ip, insert_asn_records_batch
from src.database.newflows import get_new_flows
from src.database.reputation import get_all_reputation_records, insert_reputation
from src.detect.detect_geolocation_flows import detect_geolocation_flows
from src.detect.detect_reputation_flows import detect_reputation_flows
from src.integrations import geolocation, ipasn, reputation
from src.processes import ipfix as ipfix_process
from src.processes.watchdog import required_processes
from src.routers.explore import setup_explore_routes
from src.utils.detections import process_data
from src.utils.flow_collector import process_flow_batch, run_flow_collector
from src.utils.ipfix import IPFIXDecoder
from src.utils.netflow import parse_netflow_v5_packet
from src.utils.tags import apply_tags

from test_ipfix import (
    IPV4_FIELDS, IPV6_FIELDS, make_message, make_netcontrol_message,
    make_netcontrol_record, make_netflow_packet, make_record, make_set, make_template,
)


def run_test_collector(mapping, port, source, stop_event, ready, listen_address="127.0.0.1"):
    def log_ready(logger, message):
        if "collector listening" in message:
            ready.put(source)

    parser = IPFIXDecoder().parse_packet if source == "ipfix" else parse_netflow_v5_packet
    with patch.dict(const.TABLE_DB_MAP, mapping), patch(
        "src.utils.locallogging.get_config_settings_detached", return_value={}
    ), patch("src.utils.locallogging.SITE", "TEST"), patch(
        "src.utils.locallogging.insert_action_detached"
    ), patch("src.utils.flow_collector.log_info", side_effect=log_ready):
        run_flow_collector(listen_address, port, parser, source, source, stop_event=stop_event)


class FlowCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.mapping = {
            table: os.path.join(self.temp.name, f"{table}.db")
            for table in const.TABLE_DB_MAP
        }
        patcher = patch.dict(const.TABLE_DB_MAP, self.mapping)
        patcher.start()
        self.addCleanup(patcher.stop)
        for target, kwargs in (
            ("src.utils.locallogging.SITE", {"new": "TEST"}),
            ("src.utils.locallogging.insert_action_detached", {}),
        ):
            patcher = patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch("src.utils.locallogging.get_config_settings_detached", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)
        schemas = {
            "configuration": const.CONST_CREATE_CONFIG_SQL,
            "newflows": const.CONST_CREATE_NEWFLOWS_SQL,
            "allflows": const.CONST_CREATE_ALLFLOWS_SQL,
            "localhosts": const.CONST_CREATE_LOCALHOSTS_SQL,
            "trafficstats": const.CONST_CREATE_TRAFFICSTATS_SQL,
            "ignorelist": const.CONST_CREATE_IGNORELIST_SQL,
            "geolocation": const.CONST_CREATE_GEOLOCATION_SQL,
            "ipasn": const.CONST_CREATE_IPASN_SQL,
            "explore": const.CONST_CREATE_EXPLORE_SQL,
            "dnskeyvalue": const.CONST_CREATE_DNSKEYVALUE_SQL,
            "reputationlist": const.CONST_CREATE_REPUTATIONLIST_SQL,
            "dbperformance": const.CONST_CREATE_DBPERFORMANCE_SQL,
        }
        for table, schema in schemas.items():
            with closing(sqlite3.connect(self.mapping[table])) as conn, conn:
                conn.executescript(schema)
                conn.execute("PRAGMA journal_mode=WAL")
        # dnskeyvalue and explore normally share a database.
        with closing(sqlite3.connect(self.mapping["dnskeyvalue"])) as conn, conn:
            conn.executescript(const.CONST_CREATE_DNSKEYVALUE_SQL)
        self.config = {
            "LocalNetworks": json.dumps([
                {"cidr": "192.168.1.0/24", "router": "192.168.1.1"},
                {"cidr": "2001:db8::/64", "ip_version": 6, "router": "2001:db8::1"},
            ]),
            "TagEntries": "[]", "CollectorProcessingInterval": 1,
            "WriteNewFlowsToCsv": 0, "ScheduleProcessor": 1, "CleanNewFlows": 1,
            "LocalFlowsDetection": 1, "StartIpfixCollector": 1,
            "CollectorInitialized": 1, "AlertOnCustomTags": 1,
        }
        with closing(sqlite3.connect(self.mapping["configuration"])) as conn, conn:
            conn.executemany("INSERT INTO configuration (key, value) VALUES (?, ?)", self.config.items())

    def query(self, table, sql, params=()):
        with closing(sqlite3.connect(self.mapping[table])) as conn:
            return conn.execute(sql, params).fetchall()

    def ingest(self, source, src=None, dst=None):
        if source == "netflow":
            packet = make_netflow_packet(src or "192.168.1.10", dst or "8.8.8.8")
            parser = parse_netflow_v5_packet
        else:
            src, dst = src or "192.168.1.10", dst or "8.8.8.8"
            fields = IPV6_FIELDS if ":" in src else IPV4_FIELDS
            packet = make_message(make_template(fields), make_set(256, make_record(src, dst)))
            parser = IPFIXDecoder().parse_packet
        process_flow_batch([(packet, ("192.0.2.1", 12345))], parser, source, source, self.config, [])

    def test_both_collectors_upsert_the_same_flow_without_overwriting_metrics(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(self.ingest, ("netflow", "ipfix")))
        rows = get_new_flows()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0][5], rows[0][6], rows[0][10]), (5, 500, 2))
        metrics = get_config_settings()
        self.assertEqual(
            (metrics["TotalPackets"], metrics["TotalFlows"], metrics["TotalBytes"]),
            (5, 2, 500),
        )
        self.assertEqual((metrics["LastPackets"], metrics["LastFlows"], metrics["LastBytes"]), (5, 2, 500))
        last_seen = metrics["LastFlowSeen"]
        self.assertTrue(update_flow_metrics(0, 0, 0, source="ipfix"))
        metrics = get_config_settings()
        self.assertEqual((metrics["LastPackets"], metrics["LastFlows"], metrics["LastBytes"]), (2, 1, 200))
        self.assertEqual(metrics["LastFlowSeen"], last_seen)
        self.assertEqual(metrics["TotalPackets"], 5)

    def test_atomic_metrics_with_concurrent_updates(self):
        def update(source):
            return [update_flow_metrics(2, 1, 200, source=source) for _ in range(20)]
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(update, ("netflow", "ipfix")))
        self.assertTrue(all(all(result) for result in results))
        metrics = get_config_settings()
        self.assertEqual((metrics["TotalPackets"], metrics["TotalFlows"], metrics["TotalBytes"]), (80, 40, 8000))

    def test_metric_failure_rolls_back_and_logs(self):
        with closing(sqlite3.connect(self.mapping["configuration"])) as conn, conn:
            conn.execute("INSERT INTO configuration (key, value) VALUES ('TotalPackets', 'invalid')")
        with patch("src.database.configuration.log_error") as error:
            self.assertFalse(update_flow_metrics(1, 1, 10, source="ipfix"))
        error.assert_called_once()
        self.assertNotIn("TotalFlows", get_config_settings())

    def test_bad_datagram_does_not_drop_subsequent_good_datagrams(self):
        packet = make_message(make_template(IPV4_FIELDS), make_set(256, make_record()))
        decoder = IPFIXDecoder()
        with patch("src.utils.flow_collector.log_warn") as error:
            process_flow_batch(
                [(b"bad", ("192.0.2.1", 1)), (packet, ("192.0.2.1", 1))],
                decoder.parse_packet, "IPFIX", "ipfix", self.config, [],
            )
        error.assert_called_once()
        self.assertEqual(len(get_new_flows()), 1)

    def test_netcontrol_export_times_and_receipt_survive_shared_storage_and_processing(self):
        start_ms, end_ms, received_at = 1700000000123, 1700000005456, 1700000060
        packet = make_netcontrol_message(
            [make_netcontrol_record(start_ms=start_ms, end_ms=end_ms)],
            [make_netcontrol_record("2001:db8::10", "2001:db8::20", start_ms=start_ms, end_ms=end_ms)],
        )
        process_flow_batch(
            [(packet, ("192.0.2.1", 54321), received_at)],
            IPFIXDecoder().parse_packet, "IPFIX", "ipfix", self.config, [],
        )
        expected_start = datetime.fromtimestamp(start_ms // 1000).strftime("%Y-%m-%d %H:%M:%S") + ".123"
        expected_end = datetime.fromtimestamp(end_ms // 1000).strftime("%Y-%m-%d %H:%M:%S") + ".456"
        expected_receipt = datetime.fromtimestamp(received_at).strftime("%Y-%m-%d %H:%M:%S")
        rows = get_new_flows()
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(tuple(row[7:10]), (expected_start, expected_end, expected_receipt))
            self.assertEqual((row[5], row[6]), (3, 300))
        with patch("src.detect.local_flows_detection.handle_alert"):
            process_data()
        self.assertEqual(
            self.query("allflows", "SELECT flow_start, flow_end, last_seen FROM allflows"),
            [(expected_start, expected_end, expected_receipt)] * 2,
        )
        self.assertEqual(get_config_settings()["TotalPackets"], 6)

    def test_reordered_segments_preserve_earliest_start_latest_end_and_arrival(self):
        decoder = IPFIXDecoder()
        for start_ms, end_ms, received_at in (
            (1700000005000, 1700000010000, 1700000060),
            (1700000001000, 1700000004000, 1700000061),
        ):
            process_flow_batch(
                [(make_netcontrol_message([make_netcontrol_record(start_ms=start_ms, end_ms=end_ms)]),
                  ("192.0.2.1", 1), received_at)],
                decoder.parse_packet, "IPFIX", "ipfix", self.config, [],
            )
        expected_start = datetime.fromtimestamp(1700000001).strftime("%Y-%m-%d %H:%M:%S") + ".000"
        expected_end = datetime.fromtimestamp(1700000010).strftime("%Y-%m-%d %H:%M:%S") + ".000"
        expected_receipt = datetime.fromtimestamp(1700000061).strftime("%Y-%m-%d %H:%M:%S")
        row = get_new_flows()[0]
        self.assertEqual(tuple(row[7:10]), (expected_start, expected_end, expected_receipt))
        self.assertEqual((row[5], row[6], row[10]), (6, 600, 2))
        with patch("src.detect.local_flows_detection.handle_alert"):
            process_data()
        self.assertEqual(
            self.query("allflows", "SELECT flow_start, flow_end, last_seen, times_seen FROM allflows"),
            [(expected_start, expected_end, expected_receipt, 2)],
        )

    def test_ipv6_through_processing_statistics_explore_and_api(self):
        with closing(sqlite3.connect(self.mapping["localhosts"])) as conn, conn:
            conn.execute("INSERT INTO localhosts (ip_address) VALUES ('2001:db8::10')")
        self.ingest("ipfix", "2001:db8::10", "2001:db8::20")
        self.assertEqual(
            self.query("localhosts", "SELECT total_packets_src, total_bytes_src FROM localhosts WHERE ip_address = '2001:db8::10'"),
            [(3, 300)],
        )
        with patch("src.detect.local_flows_detection.handle_alert") as alert:
            process_data()
        alert.assert_called_once()
        self.assertEqual(alert.call_args.args[3], "2001:db8::10")
        self.assertEqual(get_new_flows(), [])
        self.assertEqual(self.query("allflows", "SELECT src_ip, dst_ip, packets, bytes FROM allflows"), [("2001:db8::10", "2001:db8::20", 3, 300)])
        self.assertEqual(self.query("trafficstats", "SELECT ip_address, total_packets, total_bytes FROM trafficstats"), [("2001:db8::10", 3, 300)])
        bulk_populate_master_flow_view()
        self.assertEqual(
            self.query("explore", "SELECT src_ip_int, dst_ip_int, sum_packets, sum_bytes FROM explore"),
            [(None, None, 3, 300)],
        )
        self.assertEqual(get_flows_for_ip("2001:db8::10")[0]["dst_ip"], "2001:db8::20")
        app = Bottle()
        setup_explore_routes(app)
        statuses = []
        body = b"".join(app({
            "REQUEST_METHOD": "GET", "PATH_INFO": "/api/explore",
            "SERVER_NAME": "localhost", "SERVER_PORT": "80",
            "SERVER_PROTOCOL": "HTTP/1.1", "wsgi.url_scheme": "http",
            "wsgi.input": BytesIO(), "wsgi.errors": BytesIO(),
        }, lambda status, headers, exc_info=None: statuses.append(status)))
        self.assertTrue(statuses[0].startswith("200"))
        self.assertIn("2001:db8::10", body.decode())

    def test_ipv6_multicast_linklocal_and_custom_tags(self):
        record = IPFIXDecoder().parse_packet(
            make_message(make_template(IPV6_FIELDS), make_set(256, make_record("fe80::1", "ff02::1"))),
            ("192.0.2.1", 1),
        )[0]
        record = apply_tags(
            record, [], set(), [["IPv6", "fe80::1", "*", "*", "*"]],
            self.config, const.CONST_LINK_LOCAL_RANGE,
        )
        self.assertEqual(record["tags"], "Multicast;LinkLocal;IPv6;")
        self.assertNotIn("Broadcast;", record["tags"])

    def test_ipv6_metadata_roundtrips_and_enriches_without_overflow(self):
        network = ipaddress.ip_network("2001:db8::/32")
        start, end, mask = int(network.network_address), int(network.broadcast_address), int(network.netmask)
        self.assertEqual(insert_geolocation([(str(network), start, end, mask, "IPv6 Country")]), (1, 1))
        self.assertEqual(get_all_geolocations(), [(str(network), start, end, mask, "IPv6 Country")])
        self.assertEqual(get_country_by_ip_int(start + 10, ip_version=6), "IPv6 Country")
        self.assertEqual(insert_asn_records_batch([(str(network), start, end, mask, "64500", "IPv6 ISP")]), (True, 1))
        self.assertEqual(get_asn_for_ip("2001:db8::10")["asn"], "64500")
        self.assertTrue(insert_reputation(str(network), start, end, 32))
        self.assertEqual(get_all_reputation_records(), [(str(network), start, end, 32)])
        self.ingest("ipfix", "2001:db8::10", "2001:db8::20")
        with patch("src.detect.local_flows_detection.handle_alert"):
            process_data()
        bulk_populate_master_flow_view()
        flow = get_flows_for_ip("2001:db8::10")[0]
        self.assertEqual((flow["src_country"], flow["dst_asn"], flow["src_isp"]), ("IPv6 Country", "64500", "IPv6 ISP"))

    def test_low_ipv6_integer_does_not_match_ipv4_enrichment_or_detection(self):
        self.assertEqual(insert_geolocation([("0.0.0.0/8", 0, 16777215, 4278190080, "IPv4 Country")]), (1, 1))
        self.assertIsNone(get_country_by_ip_int(1, ip_version=6))
        self.assertEqual(insert_asn_records_batch([("0.0.0.0/8", 0, 16777215, 8, "1", "IPv4 ISP")]), (True, 1))
        self.assertIsNone(get_asn_for_ip("::1"))
        row = ["2001:db8::10", "::1", 50000, 443, 6, 3, 300, "", "", "", 1, ""]
        with patch("src.detect.detect_geolocation_flows.handle_alert") as geo_alert:
            detect_geolocation_flows([row], {"BannedCountryList": "IPv4 Country"}, get_all_geolocations())
        geo_alert.assert_not_called()
        with patch("src.detect.detect_reputation_flows.handle_alert") as reputation_alert:
            detect_reputation_flows([row], self.config, [("0.0.0.0/8", 0, 16777215, 8)])
        reputation_alert.assert_not_called()

    def test_ipv6_reputation_and_geolocation_detections(self):
        network = ipaddress.ip_network("2001:db8::/32")
        start, end, mask = int(network.network_address), int(network.broadcast_address), int(network.netmask)
        self.ingest("ipfix", "2001:db8::10", "2001:db8::20")
        rows = get_new_flows()
        with patch("src.detect.detect_reputation_flows.handle_alert") as alert:
            detect_reputation_flows(rows, self.config, [(str(network), start, end, 32)])
        alert.assert_called_once()
        with patch("src.detect.detect_geolocation_flows.handle_alert") as alert:
            detect_geolocation_flows(rows, {"BannedCountryList": "Blocked"}, [(str(network), start, end, mask, "Blocked")])
        alert.assert_called_once()

    def test_ipv6_reputation_import_with_ipv4_exclusions(self):
        with patch.object(reputation.requests, "get") as get:
            get.return_value.text = "192.0.2.0/24\n2001:db8::/32\n"
            reputation.import_reputation_list({
                "ReputationUrl": "https://example.invalid/list",
                "ReputationListRemove": "192.0.2.0/24",
            })
        records = get_all_reputation_records()
        self.assertEqual([row[0] for row in records], ["2001:db8::/32"])
        self.assertEqual(records[0][1], int(ipaddress.ip_address("2001:db8::")))

    def test_maxmind_import_reads_both_address_families_and_local_ipv6(self):
        for filename, data in (
            ("GeoLite2-Country-Locations-en.csv", "geoname_id,country_name\n1,Example\n"),
            ("GeoLite2-Country-Blocks-IPv4.csv", "network,geoname_id\n192.0.2.0/24,1\n"),
            ("GeoLite2-Country-Blocks-IPv6.csv", "network,geoname_id\n2001:db9::/32,1\n"),
        ):
            Path(self.temp.name, filename).write_text(data, encoding="utf-8")
        with patch.object(geolocation, "CONST_GEOLOCATION_DB", self.mapping["geolocation"]), patch.object(
            geolocation, "get_config_settings", return_value={**self.config, "MaxMindAPIKey": "test-key"}
        ), patch.object(geolocation.requests, "get") as get:
            get.return_value.status_code = 503
            geolocation.create_geolocation_db()
        networks = {row[0] for row in get_all_geolocations()}
        self.assertTrue({"192.0.2.0/24", "2001:db9::/32", "2001:db8::/64", "ff00::/8"}.issubset(networks))
        self.assertEqual(geolocation.lookup_ip_country("2001:db9::1"), "Example")

    def test_asn_import_reads_combined_ipv4_ipv6_data(self):
        Path(self.temp.name, "asn_full.json").write_text(json.dumps({
            "64500": {
                "ipv4": ["192.0.2.0/24"], "ipv6": ["2001:db8::/32"],
                "organization": {"name": "Example ISP"},
            },
        }), encoding="utf-8")
        with patch.object(ipasn, "CONST_IPASN_DB", self.mapping["ipasn"]), patch.object(
            ipasn, "_get_remote_etag", return_value=None
        ), patch.object(ipasn, "_download_with_resume", return_value=""), patch.object(
            ipasn.zipfile, "ZipFile"
        ):
            ipasn.create_asn_database()
        self.assertEqual(get_asn_for_ip("192.0.2.1")["asn"], "64500")
        self.assertEqual(get_asn_for_ip("2001:db8::1")["isp_name"], "Example ISP")

    def test_live_udp_collectors_coexist_in_separate_processes(self):
        ports = []
        for _ in range(2):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
                listener.bind(("127.0.0.1", 0))
                ports.append(listener.getsockname()[1])
        ctx = multiprocessing.get_context("spawn")
        stop_event = ctx.Event()
        ready = ctx.Queue()
        processes = [
            ctx.Process(target=run_test_collector, args=(self.mapping, port, source, stop_event, ready))
            for port, source in zip(ports, ("netflow", "ipfix"))
        ]
        try:
            for process in processes:
                process.start()
            self.assertEqual({ready.get(timeout=15), ready.get(timeout=15)}, {"netflow", "ipfix"})
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as exporter:
                exporter.sendto(make_netflow_packet(), ("127.0.0.1", ports[0]))
                exporter.sendto(
                    make_netcontrol_message([make_netcontrol_record()]),
                    ("127.0.0.1", ports[1]),
                )
                largest_packet = make_netcontrol_message(
                    ipv6=[make_netcontrol_record("2001:db8::10", "2001:db8::20")] * 30,
                )
                self.assertEqual(len(largest_packet), 2416)
                exporter.sendto(
                    largest_packet,
                    ("127.0.0.1", ports[1]),
                )
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                rows = self.query("newflows", "SELECT packets, bytes FROM newflows ORDER BY src_ip")
                if rows == [(5, 500), (90, 9000)] and get_config_settings().get("TotalFlows") == 32:
                    break
                time.sleep(0.05)
            self.assertEqual(rows, [(5, 500), (90, 9000)])
            self.assertEqual(get_config_settings()["TotalFlows"], 32)
            self.assertTrue(all(process.is_alive() for process in processes))
        finally:
            stop_event.set()
            for process in processes:
                if process.pid is not None:
                    process.join(timeout=5)
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=5)
            ready.close()
            ready.join_thread()
        self.assertEqual([process.exitcode for process in processes], [0, 0])

    @unittest.skipUnless(socket.has_ipv6, "IPv6 transport is unavailable")
    def test_live_ipv6_udp_transport_accepts_both_record_families(self):
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as listener:
                listener.bind(("::1", 0))
                port = listener.getsockname()[1]
        except OSError as exc:
            self.skipTest(f"IPv6 loopback is unavailable: {exc}")
        ctx = multiprocessing.get_context("spawn")
        stop_event, ready = ctx.Event(), ctx.Queue()
        process = ctx.Process(
            target=run_test_collector,
            args=(self.mapping, port, "ipfix", stop_event, ready, "::1"),
        )
        try:
            process.start()
            self.assertEqual(ready.get(timeout=15), "ipfix")
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as exporter:
                exporter.sendto(
                    make_netcontrol_message(
                        [make_netcontrol_record()],
                        [make_netcontrol_record("2001:db8::10", "2001:db8::20")],
                    ),
                    ("::1", port),
                )
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                rows = self.query("newflows", "SELECT packets, bytes FROM newflows")
                if rows == [(3, 300)] * 2 and get_config_settings().get("TotalFlows") == 2:
                    break
                time.sleep(0.05)
            self.assertEqual(rows, [(3, 300)] * 2)
            self.assertEqual(get_config_settings()["TotalFlows"], 2)
            self.assertTrue(process.is_alive())
        finally:
            stop_event.set()
            if process.pid is not None:
                process.join(timeout=5)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            ready.close()
            ready.join_thread()
        self.assertEqual(process.exitcode, 0)

    def test_ipfix_waits_for_bootstrap_and_independent_enable_flag(self):
        with patch.object(ipfix_process, "collector_dependencies_ready", return_value=True), patch.object(
            ipfix_process, "get_config_settings", side_effect=[
                {"CollectorInitialized": 0, "StartIpfixCollector": 1},
                {"CollectorInitialized": 1, "StartIpfixCollector": "0"},
                {"CollectorInitialized": 1, "StartIpfixCollector": "1", "StartCollector": 0},
            ]
        ), patch.object(ipfix_process.time, "sleep") as sleep, patch.object(
            ipfix_process, "handle_ipfix"
        ) as handle:
            ipfix_process.main()
        handle.assert_called_once_with()
        self.assertEqual(sleep.call_count, 3)

    def test_ipfix_dependency_check_does_not_clear_queued_flows(self):
        self.ingest("netflow")
        self.assertTrue(ipfix_process.collector_dependencies_ready())
        self.assertEqual(len(get_new_flows()), 1)

    def test_supervisor_watchdog_and_defaults_include_both_collectors(self):
        config = configparser.ConfigParser()
        config.read(Path(__file__).resolve().parents[1] / "src" / "super.conf")
        for name in ("collector", "ipfix"):
            self.assertIn(name, required_processes)
            self.assertEqual(config[f"program:{name}"]["command"], f"python -m src.processes.{name}")
            self.assertEqual(config[f"program:{name}"]["autostart"], "true")
            self.assertEqual(config[f"program:{name}"]["autorestart"], "true")
        defaults = dict(const.CONST_INSTALL_CONFIGS)
        self.assertEqual((defaults["StartCollector"], defaults["StartIpfixCollector"]), ("1", "1"))
        self.assertNotEqual(const.CONST_COLLECTOR_LISTEN_PORT, const.CONST_IPFIX_LISTEN_PORT)


if __name__ == "__main__":
    unittest.main()
