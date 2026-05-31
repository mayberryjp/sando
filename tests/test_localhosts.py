import unittest
from unittest.mock import patch

from src.database import localhosts


class LocalhostsDatabaseTests(unittest.TestCase):
    def test_get_localhosts_all_includes_last_seen_column(self):
        class FakeCursor:
            description = [
                ("ip_address",),
                ("last_seen",),
            ]

            def execute(self, query):
                self.query = query

            def fetchall(self):
                return [("192.0.2.10", "2026-05-31 07:49:00")]

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
        self.assertEqual(
            result,
            [{"ip_address": "192.0.2.10", "last_seen": "2026-05-31 07:49:00"}],
        )


if __name__ == "__main__":
    unittest.main()
