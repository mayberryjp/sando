import json
import os
import socket
import sqlite3
import struct
import tempfile
import time
import unittest
from io import BytesIO
from unittest.mock import Mock, patch

from bottle import Bottle

from src.const import CONST_CREATE_DHCPLOGS_SQL, TABLE_DB_MAP
from src.database.core import create_table
from src.database.dhcplogs import delete_aged_dhcp_logs, get_dhcp_logs, insert_dhcp_log
from src.processes.dhcpserver import DHCPServer
from src.routers.dhcplogs import setup_dhcplogs_routes


class DHCPLogTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.executescript(CONST_CREATE_DHCPLOGS_SQL)
        for target, kwargs in (
            ("src.database.dhcplogs.connect_to_db", {"return_value": self.conn}),
            ("src.database.dhcplogs.disconnect_from_db", {}),
            ("src.processes.dhcpserver.log_info", {}),
            ("src.processes.dhcpserver.log_warn", {}),
            ("src.processes.dhcpserver.log_error", {}),
            ("src.processes.dhcpserver.update_localhost_last_dhcp_discover", {}),
            ("src.processes.dhcpserver.get_config_settings", {"return_value": {}}),
            ("src.routers.dhcplogs.log_warn", {}),
            ("src.routers.dhcplogs.log_error", {}),
        ):
            patcher = patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.scope = {
            "cidr": "192.168.30.0/24",
            "subnet_mask": "255.255.255.0",
            "firewall_interface_name": "VLAN30",
            "lease_time": 3600,
        }
        self.server = DHCPServer("192.168.1.2", {}, scopes=[self.scope])
        self.server.sock = Mock()
        self.server.reload_scopes = Mock()
        self.server._get_registered_ip = Mock(return_value="192.168.30.20")
        self.app = Bottle()
        setup_dhcplogs_routes(self.app)

    def packet_bytes(self, message=1, relay="192.168.30.1", requested=None):
        data = bytearray(240)
        data[:3] = bytes([1, 1, 6])
        data[4:8] = struct.pack("!I", 0x00ABCDEF)
        data[24:28] = socket.inet_aton(relay)
        data[28:34] = bytes.fromhex("98173ca68628")
        data[236:240] = b"\x63\x82\x53\x63"
        data.extend(bytes([53, 1, message, 12, 4]) + b"test")
        if requested:
            data.extend(bytes([50, 4]) + socket.inet_aton(requested))
        data.append(255)
        return bytes(data)

    def process_packet(self, data):
        def receive(_size):
            self.server.running = False
            return data, ("0.0.0.0", 68)
        self.server.sock.recvfrom.side_effect = receive
        self.server.serve_forever()

    def api_get(self, query=""):
        statuses = []
        body = b"".join(self.app({
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/dhcp/logs",
            "QUERY_STRING": query,
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "wsgi.url_scheme": "http",
            "wsgi.input": BytesIO(),
            "wsgi.errors": BytesIO(),
        }, lambda status, headers, exc_info=None: statuses.append(status)))
        return int(statuses[0].split()[0]), json.loads(body)

    def test_discover_and_request_log_received_and_sent_details(self):
        self.process_packet(self.packet_bytes())
        self.process_packet(self.packet_bytes(3, requested="192.168.30.20"))
        status, body = self.api_get()
        self.assertEqual(status, 200)
        logs = body["logs"]
        self.assertEqual(body["total"], 4)
        self.assertEqual(
            [(row["event"], row["dhcp_message"]) for row in reversed(logs)],
            [("request_received", "Discover"), ("reply_sent", "Offer"),
             ("request_received", "Request"), ("reply_sent", "ACK")],
        )
        ack = logs[0]
        self.assertEqual(
            set(ack),
            {"id", "timestamp", "interface", "event", "dhcp_message", "peer",
             "transaction_id", "client_mac", "reason", "details"},
        )
        self.assertEqual(ack["interface"], "VLAN30")
        self.assertEqual(ack["peer"], "192.168.30.1:67")
        self.assertEqual(ack["transaction_id"], "00abcdef")
        self.assertEqual(ack["client_mac"], "98:17:3C:A6:86:28")
        self.assertEqual(ack["details"]["yiaddr"], "192.168.30.20")
        self.assertEqual(ack["details"]["lease_time"], 3600)
        self.assertEqual(logs[-1]["details"]["hostname"], "test")
        self.assertEqual(logs[1]["details"]["requested_ip"], "192.168.30.20")
        self.assertRegex(ack["timestamp"], r"[+-]\d\d:\d\d$")
        self.assertEqual(self.server.sock.sendto.call_count, 2)

    def test_ignored_requests_and_naks_include_reasons(self):
        self.server._get_registered_ip.return_value = None
        self.process_packet(self.packet_bytes())
        self.assertEqual(get_dhcp_logs()["logs"][0]["reason"], "Unregistered MAC")
        self.server.sock.sendto.assert_not_called()
        self.process_packet(self.packet_bytes(3, requested="192.168.30.20"))
        nak = get_dhcp_logs()["logs"][0]
        self.assertEqual(nak["event"], "reply_sent")
        self.assertEqual(nak["dhcp_message"], "NAK")
        self.assertEqual(nak["reason"], "Unregistered MAC")
        with patch("src.processes.dhcpserver.get_config_settings",
                   return_value={"DhcpPassiveMonitoring": "1"}):
            self.process_packet(self.packet_bytes())
        self.assertEqual(get_dhcp_logs()["logs"][0]["reason"], "Passive monitoring enabled")

    def test_malformed_packets_log_error_without_reply(self):
        valid = self.packet_bytes()
        for data in (
            b"short",
            valid[:236] + b"bad!" + valid[240:],
            valid[:240] + bytes([53]),
            valid[:240] + bytes([53, 1]),
            valid[:240] + bytes([53, 0, 255]),
        ):
            with self.subTest(data=data):
                self.process_packet(data)
                row = get_dhcp_logs()["logs"][0]
                self.assertEqual(row["event"], "processing_error")
                self.assertTrue(row["reason"])
                self.assertEqual(row["peer"], "0.0.0.0:68")
        self.server.sock.sendto.assert_not_called()

    def test_failed_send_is_not_logged_as_success(self):
        self.server.sock.sendto.side_effect = OSError("Network unreachable")
        self.process_packet(self.packet_bytes())
        logs = get_dhcp_logs()["logs"]
        self.assertEqual(logs[0]["event"], "send_failed")
        self.assertEqual(logs[0]["reason"], "Network unreachable")
        self.assertNotIn("reply_sent", [row["event"] for row in logs])

    def test_database_failure_does_not_prevent_dhcp_response(self):
        with patch("src.database.dhcplogs.connect_to_db", return_value=None), patch(
            "src.processes.dhcpserver.log_error"
        ) as log_error:
            self.process_packet(self.packet_bytes())
        self.server.sock.sendto.assert_called_once()
        self.assertEqual(log_error.call_count, 2)

    def test_worker_lifecycle(self):
        sock = Mock()
        with patch("src.processes.dhcpserver.socket.socket", return_value=sock):
            self.server.start()
        self.server.stop()
        self.assertEqual(
            [row["event"] for row in get_dhcp_logs()["logs"]],
            ["worker_stopped", "worker_started"],
        )
        sock.close.assert_called_once()

    def test_retention_filters_and_stable_pagination(self):
        now = time.time()
        with patch("src.database.dhcplogs.time.time", return_value=now):
            for i in range(3):
                insert_dhcp_log("request_received", client_mac="98:17:3c:a6:86:28",
                                transaction_id="00abcdef", interface="VLAN30",
                                details={"sequence": i})
            self.conn.execute("UPDATE dhcplogs SET timestamp = ? WHERE id = 1",
                              (now - 7 * 86400 - 1,))
            insert_dhcp_log("worker_started")
            self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM dhcplogs").fetchone()[0], 3)
            status, body = self.api_get(
                "client_mac=98:17:3c:a6:86:28&transaction_id=00ABCDEF"
                "&event=request_received&interface=VLAN30&limit=1&offset=1"
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["total"], 2)
            self.assertEqual(body["logs"][0]["details"], {"sequence": 1})
            self.assertEqual((body["limit"], body["offset"]), (1, 1))
            self.assertEqual(self.api_get("limit=0")[1]["logs"], [])
            self.assertEqual(self.api_get("offset=20")[1]["logs"], [])
        with patch("src.database.dhcplogs.time.time", return_value=now + 8 * 86400):
            delete_aged_dhcp_logs()
            self.assertEqual(
                self.conn.execute("SELECT COUNT(*) FROM dhcplogs").fetchone()[0], 0
            )
            self.assertEqual(self.api_get()[1]["total"], 0)

    def test_invalid_queries_and_database_errors(self):
        for query in (
            "limit=-1", "offset=abc", "limit=", "limit=1.5",
            "offset=9223372036854775808", "client_mac=bad",
            "transaction_id=bad", "event=", "interface=",
        ):
            with self.subTest(query=query), patch(
                "src.routers.dhcplogs.get_dhcp_logs"
            ) as get_logs:
                status, body = self.api_get(query)
                self.assertEqual(status, 400)
                self.assertIn("error", body)
                get_logs.assert_not_called()
        with patch("src.database.dhcplogs.connect_to_db", return_value=None):
            status, body = self.api_get()
        self.assertEqual(status, 500)
        self.assertIn("error", body)
        self.assertNotIn("logs", body)


class DHCPLogPersistenceTests(unittest.TestCase):
    def test_events_survive_reconnect_and_schema_initialization(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            TABLE_DB_MAP, {"dhcplogs": os.path.join(directory, "dhcplogs.db")}
        ), patch("src.database.core.log_info"):
            create_table(CONST_CREATE_DHCPLOGS_SQL, "dhcplogs")
            insert_dhcp_log("worker_started", details={"server_ip": "192.168.1.2"})
            create_table(CONST_CREATE_DHCPLOGS_SQL, "dhcplogs")
            status = get_dhcp_logs()
            self.assertEqual(status["total"], 1)
            self.assertEqual(status["logs"][0]["event"], "worker_started")
            self.assertEqual(status["logs"][0]["details"], {"server_ip": "192.168.1.2"})
