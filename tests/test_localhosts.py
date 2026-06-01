import sqlite3
import unittest
from unittest.mock import patch

from src.database import common, localhosts


class LocalhostsDatabaseTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
