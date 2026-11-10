import json
import sqlite3
import unittest
from io import BytesIO
from unittest.mock import patch

from bottle import Bottle

from src.const import CONST_CREATE_ALERTS_SQL
from src.routers.alerts import setup_alerts_routes


class AlertsPaginationTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.executescript(CONST_CREATE_ALERTS_SQL)
        self.conn.executemany(
            """
            INSERT INTO alerts (
                id, ip_address, flow, category, alert_enrichment_1,
                alert_enrichment_2, times_seen, first_seen, last_seen, acknowledged
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    f"alert-{i:03d}", "192.168.1.2", "flow", "Test",
                    "enrichment-1", "enrichment-2", 3,
                    f"2026-11-{1 + i // 10:02d} 00:00:00",
                    "2026-11-30 00:00:00", i % 2,
                )
                for i in range(235)
            ],
        )
        for target, kwargs in (
            ("src.database.alerts.connect_to_db", {"return_value": self.conn}),
            ("src.database.alerts.disconnect_from_db", {}),
            ("src.database.alerts.log_info", {}),
            ("src.database.core.log_info", {}),
            ("src.database.core.insert_dbperformance", {}),
            ("src.routers.alerts.log_info", {}),
            ("src.routers.alerts.log_warn", {}),
            (
                "src.routers.alerts.get_localhosts_all",
                {"return_value": [
                    {"ip_address": "192.168.1.2", "local_description": "Test host"}
                ]},
            ),
        ):
            patcher = patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.app = Bottle()
        setup_alerts_routes(self.app)
        self.expected_ids = [f"alert-{i:03d}" for i in reversed(range(235))]

    def get_alerts(self, query=""):
        statuses = []
        body = b"".join(self.app({
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/alerts/recent",
            "QUERY_STRING": query,
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "wsgi.url_scheme": "http",
            "wsgi.input": BytesIO(),
            "wsgi.errors": BytesIO(),
        }, lambda status, headers, exc_info=None: statuses.append(status)))
        return int(statuses[0].split()[0]), json.loads(body)

    def assert_page(self, query, expected_ids):
        status, alerts = self.get_alerts(query)
        self.assertEqual(status, 200)
        self.assertEqual([alert["id"] for alert in alerts], expected_ids)
        return alerts

    def test_default_returns_all_alerts_and_preserves_response_shape(self):
        alerts = self.assert_page("", self.expected_ids)
        self.assertEqual(set(alerts[0]), {
            "id", "ip_address", "flow", "category", "alert_enrichment_1",
            "alert_enrichment_2", "times_seen", "first_seen", "last_seen",
            "acknowledged", "local_description",
        })
        self.assertIs(alerts[0]["acknowledged"], False)
        self.assertEqual(alerts[0]["local_description"], "Test host")

    def test_limit_has_no_100_row_cap(self):
        self.assert_page("limit=150", self.expected_ids[:150])

    def test_limit_and_offset_return_requested_slice(self):
        self.assert_page("limit=50&offset=100", self.expected_ids[100:150])

    def test_pages_cover_all_alerts_without_gaps_or_duplicates(self):
        ids = []
        for offset in range(0, 250, 50):
            _, alerts = self.get_alerts(f"limit=50&offset={offset}")
            ids.extend(alert["id"] for alert in alerts)
        self.assertEqual(ids, self.expected_ids)

    def test_offset_without_limit_returns_all_remaining_alerts(self):
        self.assert_page("offset=100", self.expected_ids[100:])

    def test_zero_limit_returns_empty_page(self):
        self.assert_page("limit=0", [])

    def test_offset_beyond_end_returns_empty_page(self):
        self.assert_page("limit=50&offset=300", [])

    def test_empty_database_returns_empty_array(self):
        self.conn.execute("DELETE FROM alerts")
        self.assert_page("", [])

    def test_invalid_pagination_returns_400_before_database_access(self):
        for query in (
            "limit=-1", "offset=-1", "limit=abc", "offset=abc",
            "limit=1.5", "offset=1.5", "limit=", "offset=",
        ):
            with self.subTest(query=query), patch(
                "src.routers.alerts.get_recent_alerts_database"
            ) as get_rows, patch(
                "src.routers.alerts.get_localhosts_all"
            ) as get_hosts:
                status, body = self.get_alerts(query)
                self.assertEqual(status, 400)
                self.assertIn("error", body)
                get_rows.assert_not_called()
                get_hosts.assert_not_called()
