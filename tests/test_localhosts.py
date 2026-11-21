import json
import sqlite3
import unittest
from io import BytesIO, StringIO
from unittest.mock import patch

from bottle import Bottle

from src.const import CONST_CREATE_LOCALHOSTS_SQL
from src.database import common, localhosts
from src.routers.localhosts import setup_localhosts_routes


class LocalhostsDatabaseTests(unittest.TestCase):
    def test_homepage_includes_maximum_current_host_threat_score(self):
        import json

        from bottle import Bottle

        from src.routers.integrations import setup_integrations_routes

        app = Bottle()
        setup_integrations_routes(app)
        homepage = next(route for route in app.routes if route.rule == "/api/homepage")

        for scores, expected in [
            ([12, 90, 35, None], 90),
            ([0, 0], 0),
            ([None], 0),
            ([], 0),
        ]:
            with self.subTest(scores=scores):

                def connect(table_name):
                    conn = sqlite3.connect(":memory:")
                    if table_name in ("alerts", "actions"):
                        conn.execute(
                            f"CREATE TABLE {table_name} (acknowledged INTEGER)"
                        )
                        return conn
                    conn.execute(
                        "CREATE TABLE localhosts (acknowledged INTEGER, threat_score INTEGER)"
                    )
                    conn.executemany(
                        "INSERT INTO localhosts VALUES (0, ?)",
                        [(score,) for score in scores],
                    )
                    return conn

                with patch(
                    "src.database.common.connect_to_db", side_effect=connect
                ), patch(
                    "src.database.common.get_average_threat_score", return_value=17
                ), patch(
                    "src.database.common.get_row_count", return_value=0
                ), patch(
                    "src.database.configuration.get_config_settings", return_value={}
                ):
                    result = json.loads(homepage.callback())

                self.assertEqual(result["maximum_threat_score"], expected)
                self.assertEqual(result["average_threat_score"], 17)

    def test_get_localhosts_all_includes_last_seen_column(self):
        class FakeCursor:
            description = [
                ("ip_address",),
                ("last_seen",),
                ("alert_if_offline",),
            ]

            def execute(self, query):
                self.query = query

            def fetchall(self):
                return [("192.0.2.10", "2026-05-31 07:49:00", 1)]

        class FakeConnection:
            def __init__(self):
                self.cursor_instance = FakeCursor()

            def cursor(self):
                return self.cursor_instance

        conn = FakeConnection()

        with patch("src.database.localhosts.connect_to_db", return_value=conn), patch(
            "src.database.localhosts.disconnect_from_db"
        ), patch(
            "src.database.localhosts.get_config_settings", return_value={}
        ):
            result = localhosts.get_localhosts_all()

        self.assertIn("last_seen", conn.cursor_instance.query)
        self.assertIn("alert_if_offline", conn.cursor_instance.query)
        self.assertEqual(
            result,
            [
                {
                    "ip_address": "192.0.2.10",
                    "last_seen": "2026-05-31 07:49:00",
                    "alert_if_offline": 1,
                    "connected_interface_name": None,
                    "connected_network": None,
                }
            ],
        )

    def test_update_localhost_alert_if_offline_by_ip(self):
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE localhosts (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                alert_if_offline INTEGER DEFAULT 1
            )
            """
        )
        conn.execute(
            "INSERT INTO localhosts (ip_address, mac_address) VALUES (?, ?)",
            ("192.0.2.20", "AA:BB:CC:DD:EE:FF"),
        )
        conn.commit()

        with patch("src.database.localhosts.connect_to_db", return_value=conn), patch(
            "src.database.localhosts.disconnect_from_db"
        ):
            result = localhosts.update_localhost_alert_if_offline("192.0.2.20", False)

        self.assertTrue(result)
        alert_if_offline = conn.execute(
            "SELECT alert_if_offline FROM localhosts WHERE ip_address = ?",
            ("192.0.2.20",),
        ).fetchone()[0]
        self.assertEqual(alert_if_offline, 0)
        conn.close()

    def test_schema21_migration_adds_alert_if_offline_default_enabled(self):
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE localhosts (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO localhosts (ip_address, mac_address) VALUES (?, ?)",
            ("192.0.2.30", "AA:BB:CC:DD:EE:00"),
        )
        conn.commit()

        with patch("src.database.common.connect_to_db", return_value=conn), patch(
            "src.database.common.disconnect_from_db"
        ):
            result = common.migrate_configurations_schema20_to_schema21()

        self.assertTrue(result)
        columns = [row[1] for row in conn.execute("PRAGMA table_info(localhosts)")]
        self.assertIn("alert_if_offline", columns)
        alert_if_offline = conn.execute(
            "SELECT alert_if_offline FROM localhosts WHERE ip_address = ?",
            ("192.0.2.30",),
        ).fetchone()[0]
        self.assertEqual(alert_if_offline, 1)
        conn.close()


class LocalhostDomainNameTests(unittest.TestCase):
    def test_update_localhost_domain_name_by_ip(self):
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE localhosts (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                domain_name TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO localhosts (ip_address, mac_address) VALUES (?, ?)",
            ("192.0.2.40", "AA:BB:CC:DD:EE:11"),
        )
        conn.commit()

        with patch("src.database.localhosts.connect_to_db", return_value=conn), patch(
            "src.database.localhosts.disconnect_from_db"
        ):
            result = localhosts.update_localhost_domain_name(
                "192.0.2.40", "server.example.com"
            )

        self.assertTrue(result)
        domain_name = conn.execute(
            "SELECT domain_name FROM localhosts WHERE ip_address = ?",
            ("192.0.2.40",),
        ).fetchone()[0]
        self.assertEqual(domain_name, "server.example.com")
        conn.close()

    def test_update_localhost_domain_name_missing_host(self):
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE localhosts (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                domain_name TEXT
            )
            """
        )
        conn.commit()

        with patch("src.database.localhosts.connect_to_db", return_value=conn), patch(
            "src.database.localhosts.disconnect_from_db"
        ):
            result = localhosts.update_localhost_domain_name(
                "198.51.100.5", "nope.example.com"
            )

        self.assertFalse(result)
        conn.close()

    def test_schema22_migration_adds_domain_name(self):
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE localhosts (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO localhosts (ip_address, mac_address) VALUES (?, ?)",
            ("192.0.2.50", "AA:BB:CC:DD:EE:22"),
        )
        conn.commit()

        with patch("src.database.common.connect_to_db", return_value=conn), patch(
            "src.database.common.disconnect_from_db"
        ):
            result = common.migrate_configurations_schema21_to_schema22()

        self.assertTrue(result)
        columns = [row[1] for row in conn.execute("PRAGMA table_info(localhosts)")]
        self.assertIn("domain_name", columns)
        conn.close()


class DockerHostTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.executescript(CONST_CREATE_LOCALHOSTS_SQL)
        self.conn.executemany(
            """
            INSERT INTO localhosts (ip_address, icon, local_description, mac_address)
            VALUES (?, ?, ?, ?)
            """,
            [
                ("192.0.2.10", "LINUX_SERVER", "Linux server", "AA:BB:CC:DD:EE:10"),
                ("192.0.2.20", "WINDOWS_SERVER", "Windows server", None),
                ("192.0.2.30", "DESKTOP", "Desktop", None),
                ("192.0.2.40", None, "Container", None),
            ],
        )
        self.conn.commit()
        config_patch = patch(
            "src.database.localhosts.get_config_settings", return_value={}
        )
        self.config = config_patch.start()
        self.addCleanup(config_patch.stop)
        for target in ("src.database.localhosts", "src.database.common"):
            for name, kwargs in [
                ("connect_to_db", {"return_value": self.conn}),
                ("disconnect_from_db", {}),
            ]:
                patcher = patch(f"{target}.{name}", **kwargs)
                patcher.start()
                self.addCleanup(patcher.stop)
        for target in (
            "src.database.localhosts.log_error",
            "src.database.common.log_error",
            "src.routers.localhosts.log_error",
        ):
            patcher = patch(target)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.app = Bottle()
        setup_localhosts_routes(self.app)

    def request(self, method, path, payload=None):
        statuses = []
        raw = json.dumps(payload).encode() if payload is not None else b""
        body = b"".join(
            self.app(
                {
                    "REQUEST_METHOD": method,
                    "PATH_INFO": path,
                    "QUERY_STRING": "",
                    "CONTENT_TYPE": "application/json",
                    "CONTENT_LENGTH": str(len(raw)),
                    "SERVER_NAME": "localhost",
                    "SERVER_PORT": "80",
                    "SERVER_PROTOCOL": "HTTP/1.1",
                    "wsgi.url_scheme": "http",
                    "wsgi.input": BytesIO(raw),
                    "wsgi.errors": StringIO(),
                },
                lambda status, headers, exc_info=None: statuses.append(status),
            )
        )
        return int(statuses[0].split()[0]), json.loads(body)

    def update(self, payload, ip="192.0.2.40"):
        return self.request("PUT", f"/api/localhosts/{ip}", payload)

    def test_connected_network_metadata_is_consistent_across_host_readers(self):
        scopes = [
            {"cidr": "10.0.0.0/8", "firewall_interface_name": "BROAD"},
            {"cidr": "10.1.10.2/24", "firewall_interface_name": "SERVER_VLAN"},
            {"cidr": "10.1.10.0/24", "firewall_interface_name": "LATER"},
            {"cidr": "2001:db8::2/64", "firewall_interface_name": "IPV6_VLAN"},
            {"cidr": "198.51.100.0/24"},
        ]
        self.config.return_value = {"LocalNetworks": json.dumps(scopes)}
        cases = [
            ("10.1.10.2", "server_vlan", "10.1.10.2/24"),
            ("2001:db8::10", "ipv6_vlan", "2001:db8::2/64"),
            ("198.51.100.10", None, "198.51.100.0/24"),
            ("203.0.113.10", None, None),
        ]
        for address, interface, network in cases:
            self.conn.execute(
                "INSERT INTO localhosts (ip_address) VALUES (?)", (address,)
            )
            with self.subTest(address=address):
                status, detail = self.request("GET", f"/api/localhosts/{address}")
                self.assertEqual(status, 200)
                for host in [
                    detail,
                    localhosts.get_localhost(address),
                    localhosts.get_localhost_as_dict(address),
                ]:
                    self.assertEqual(host["connected_interface_name"], interface)
                    self.assertEqual(host["connected_network"], network)

        self.config.reset_mock()
        status, hosts = self.request("GET", "/api/localhosts")
        self.assertEqual(status, 200)
        self.config.assert_called_once_with()
        by_ip = {host["ip_address"]: host for host in hosts}
        for address, interface, network in cases:
            self.assertEqual(by_ip[address]["connected_interface_name"], interface)
            self.assertEqual(by_ip[address]["connected_network"], network)

        self.config.return_value = {
            "LocalNetworks": json.dumps(
                [{"cidr": "10.1.10.0/24", "firewall_interface_name": "RENAMED"}]
            )
        }
        self.assertEqual(
            self.request("GET", "/api/localhosts/10.1.10.2")[1][
                "connected_interface_name"
            ],
            "renamed",
        )

    def test_network_configuration_failures_are_not_reported_as_unmatched(self):
        for config in [
            None,
            {"LocalNetworks": "not-json"},
            {"LocalNetworks": "{}"},
            {"LocalNetworks": '[{"router": "192.0.2.1"}]'},
            {"LocalNetworks": '[{"cidr": "invalid"}]'},
            {"LocalNetworks": '[{"cidr": "192.0.2.0/24", "firewall_interface_name": 1}]'},
        ]:
            with self.subTest(config=config), patch(
                "src.database.configuration.log_error"
            ):
                self.config.return_value = config
                for path in ["/api/localhosts", "/api/localhosts/192.0.2.40"]:
                    status, body = self.request("GET", path)
                    self.assertEqual(status, 500)
                    self.assertIn("error", body)
                for reader, args in [
                    (localhosts.get_localhosts_all, ()),
                    (localhosts.get_localhost, ("192.0.2.40",)),
                    (localhosts.get_localhost_as_dict, ("192.0.2.40",)),
                ]:
                    with self.assertRaises(
                        (sqlite3.OperationalError, ValueError)
                    ):
                        reader(*args)

    def test_dropdown_only_returns_linux_and_windows_servers(self):
        status, hosts = self.request("GET", "/api/localhosts/docker-hosts")
        self.assertEqual(status, 200)
        self.assertEqual(
            hosts,
            [
                {
                    "ip_address": "192.0.2.10",
                    "local_description": "Linux server",
                    "icon": "LINUX_SERVER",
                },
                {
                    "ip_address": "192.0.2.20",
                    "local_description": "Windows server",
                    "icon": "WINDOWS_SERVER",
                },
            ],
        )
        self.conn.execute("UPDATE localhosts SET icon = NULL")
        self.assertEqual(self.request("GET", "/api/localhosts/docker-hosts"), (200, []))

    def test_container_reference_round_trips_through_host_readers(self):
        for icon, server in [
            ("DOCKER_CONTAINER", "192.0.2.10"),
            ("DOCKER CONTAINER", "192.0.2.20"),
        ]:
            with self.subTest(icon=icon):
                self.assertEqual(
                    self.update(
                        {
                            "icon": icon,
                            "docker_host": server,
                        }
                    )[0],
                    200,
                )
                status, host = self.request("GET", "/api/localhosts/192.0.2.40")
                self.assertEqual(status, 200)
                self.assertEqual(host["icon"], "DOCKER_CONTAINER")
                self.assertEqual(host["docker_host"], server)
                status, hosts = self.request("GET", "/api/localhosts")
                self.assertEqual(status, 200)
                container = next(h for h in hosts if h["ip_address"] == "192.0.2.40")
                self.assertEqual(container["docker_host"], server)
                self.assertEqual(
                    localhosts.get_localhost("192.0.2.40")["docker_host"], server
                )
                self.assertEqual(
                    localhosts.get_localhost_as_dict("192.0.2.40")["docker_host"],
                    server,
                )

    def test_optional_reference_can_be_omitted_preserved_or_cleared(self):
        self.assertEqual(self.update({"icon": "DOCKER_CONTAINER"})[0], 200)
        self.assertIsNone(localhosts.get_localhost("192.0.2.40")["docker_host"])
        self.assertEqual(self.update({"docker_host": "192.0.2.10"})[0], 200)
        self.assertEqual(
            self.update({"local_description": "Renamed container"})[0], 200
        )
        self.assertEqual(
            localhosts.get_localhost("192.0.2.40")["docker_host"], "192.0.2.10"
        )
        self.assertEqual(self.update({"docker_host": None})[0], 200)
        self.assertIsNone(localhosts.get_localhost("192.0.2.40")["docker_host"])
        self.assertEqual(self.update({"docker_host": "192.0.2.10"})[0], 200)
        self.assertEqual(self.update({"icon": "DESKTOP"})[0], 200)
        self.assertIsNone(localhosts.get_localhost("192.0.2.40")["docker_host"])

    def test_invalid_references_do_not_change_host(self):
        before = self.conn.execute("SELECT * FROM localhosts").fetchall()
        for icon, server in [
            ("DOCKER_CONTAINER", "192.0.2.99"),
            ("DOCKER_CONTAINER", "192.0.2.30"),
            ("DOCKER_CONTAINER", "192.0.2.40"),
            ("DOCKER_CONTAINER", "freeform.example.com"),
            ("DOCKER_CONTAINER", ""),
            ("DOCKER_CONTAINER", 123),
            ("DOCKER_CONTAINER", False),
            ("DOCKER_CONTAINER", []),
            ("DOCKER_CONTAINER", {}),
            ("DESKTOP", "192.0.2.10"),
        ]:
            with self.subTest(icon=icon, server=server):
                status, payload = self.update({"icon": icon, "docker_host": server})
                self.assertEqual(status, 400)
                self.assertIn("error", payload)
                self.assertEqual(
                    self.conn.execute("SELECT * FROM localhosts").fetchall(), before
                )

    def test_server_rename_and_reclassification_update_references(self):
        self.assertEqual(
            self.update(
                {
                    "icon": "DOCKER_CONTAINER",
                    "docker_host": "192.0.2.10",
                }
            )[0],
            200,
        )
        self.assertEqual(
            self.update(
                {"ip_address": "192.0.2.11", "icon": "LINUX_SERVER"}, ip="192.0.2.10"
            )[0],
            200,
        )
        self.assertEqual(
            localhosts.get_localhost("192.0.2.40")["docker_host"], "192.0.2.11"
        )
        self.assertEqual(self.update({"icon": "DESKTOP"}, ip="192.0.2.11")[0], 200)
        self.assertIsNone(localhosts.get_localhost("192.0.2.40")["docker_host"])

    def test_server_deletion_clears_references_by_ip_or_mac(self):
        for function in (
            localhosts.delete_localhost,
            localhosts.delete_localhost_database,
        ):
            with self.subTest(function=function.__name__):
                self.conn.execute(
                    "INSERT OR IGNORE INTO localhosts (ip_address, icon, mac_address) "
                    "VALUES ('192.0.2.10', 'LINUX_SERVER', 'AA:BB:CC:DD:EE:10')"
                )
                self.assertEqual(
                    self.update(
                        {
                            "icon": "DOCKER_CONTAINER",
                            "docker_host": "192.0.2.10",
                        }
                    )[0],
                    200,
                )
                for sql in [
                    "CREATE TABLE IF NOT EXISTS alerts (ip_address TEXT)",
                    "CREATE TABLE IF NOT EXISTS allflows (src_ip TEXT, dst_ip TEXT)",
                    "CREATE TABLE IF NOT EXISTS dnsqueries (client_ip TEXT)",
                ]:
                    self.conn.execute(sql)
                self.assertTrue(function("AA:BB:CC:DD:EE:10"))
                self.assertIsNone(localhosts.get_localhost("192.0.2.40")["docker_host"])

    def test_missing_host_and_database_failures_are_not_successful(self):
        self.assertEqual(
            self.update({"icon": "DOCKER_CONTAINER"}, ip="192.0.2.99")[0], 404
        )
        with patch("src.database.localhosts.connect_to_db", return_value=None):
            self.assertEqual(self.update({"icon": "DOCKER_CONTAINER"})[0], 500)
            self.assertEqual(
                self.request("GET", "/api/localhosts/docker-hosts")[0], 500
            )
        with patch("src.database.common.connect_to_db", return_value=None):
            self.assertFalse(common.update_database_schema("22", "23"))

    def test_migration_preserves_existing_hosts_and_is_repeatable(self):
        self.conn.execute("DROP TABLE localhosts")
        self.conn.execute(
            "CREATE TABLE localhosts (ip_address TEXT PRIMARY KEY, icon TEXT)"
        )
        self.conn.execute(
            "INSERT INTO localhosts VALUES ('192.0.2.10', 'LINUX_SERVER')"
        )
        self.conn.commit()
        self.assertTrue(common.update_database_schema("22", "23"))
        self.assertTrue(common.migrate_configurations_schema22_to_schema23())
        self.assertEqual(
            self.conn.execute("SELECT * FROM localhosts").fetchall(),
            [("192.0.2.10", "LINUX_SERVER", None)],
        )


if __name__ == "__main__":
    unittest.main()
