import json
import sqlite3
import tempfile
import unittest
from contextlib import ExitStack
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from bottle import Bottle

from src.const import (
    CONST_CREATE_ALERTS_SQL,
    CONST_CREATE_ALLFLOWS_SQL,
    CONST_CREATE_IGNORELIST_SQL,
)
from src.database.ignorelist import delete_stale_ignorelist_entries, get_ignorelist
from src.routers.ignorelist import setup_ignorelist_routes
from src.utils.tags import tag_ignorelist


class IgnorelistPortTests(unittest.TestCase):
    def setUp(self):
        self.app = Bottle()
        setup_ignorelist_routes(self.app)
        self.payload = {
            "ignorelist_id": "IgnoreList_10.4.60.13_10.4.20.17_1_0_NewOutboundDetection_Flow",
            "src_ip": "10.4.60.13",
            "dst_ip": "10.4.20.17",
            "dst_port": 0,
            "protocol": 1,
        }
        for target in ("src.routers.ignorelist.log_info", "src.routers.ignorelist.log_error"):
            logger_patch = patch(target)
            logger_patch.start()
            self.addCleanup(logger_patch.stop)

    def request(self, payload, method="POST"):
        encoded = json.dumps(payload).encode()
        statuses = []
        body = b"".join(self.app({
            "REQUEST_METHOD": method,
            "PATH_INFO": "/api/ignorelist",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(encoded)),
            "wsgi.url_scheme": "http",
            "wsgi.input": BytesIO(encoded),
            "wsgi.errors": BytesIO(),
        }, lambda status, headers, exc_info=None: statuses.append(status)))
        return int(statuses[0].split()[0]), json.loads(body)

    def test_valid_ports_are_normalized_without_losing_zero(self):
        for port, expected in [(0, 0), ("0", 0), (443, 443), ("443", 443),
                               (65535, 65535), ("65535", 65535), ("*", "*")]:
            with self.subTest(port=port), patch(
                "src.routers.ignorelist.insert_ignorelist_entry", return_value=True
            ) as insert:
                status, body = self.request(dict(self.payload, dst_port=port))
                self.assertEqual(status, 200)
                self.assertEqual(body["message"], "IgnoreList entry added successfully")
                insert.assert_called_once_with(
                    self.payload["ignorelist_id"], self.payload["src_ip"],
                    self.payload["dst_ip"], expected, 1, src_port=None,
                )

    def test_zero_port_is_not_protocol_specific(self):
        for protocol in (0, 1, 6, 17, 58):
            with self.subTest(protocol=protocol), patch(
                "src.routers.ignorelist.insert_ignorelist_entry", return_value=True
            ) as insert:
                status, _ = self.request(dict(self.payload, protocol=protocol, src_port=0))
                self.assertEqual(status, 200)
                insert.assert_called_once_with(
                    self.payload["ignorelist_id"], self.payload["src_ip"],
                    self.payload["dst_ip"], 0, protocol, src_port=0,
                )

    def test_missing_fields_are_rejected_with_correct_field_name(self):
        for field in self.payload:
            for value in (None, ""):
                with self.subTest(field=field, value=value), patch(
                    "src.routers.ignorelist.insert_ignorelist_entry"
                ) as insert:
                    status, body = self.request(dict(self.payload, **{field: value}))
                    self.assertEqual(status, 400)
                    self.assertIn("protocol", body["error"])
                    self.assertNotIn("dst_protocol", body["error"])
                    insert.assert_not_called()
            with self.subTest(field=field, missing=True), patch(
                "src.routers.ignorelist.insert_ignorelist_entry"
            ) as insert:
                payload = dict(self.payload)
                del payload[field]
                status, _ = self.request(payload)
                self.assertEqual(status, 400)
                insert.assert_not_called()

    def test_invalid_ports_are_rejected(self):
        for port in (-1, 65536, "-1", "65536", "abc", " ", "1.5", 1.5, 0.0,
                     True, False, [], {}):
            with self.subTest(port=port), patch(
                "src.routers.ignorelist.insert_ignorelist_entry"
            ) as insert:
                status, body = self.request(dict(self.payload, dst_port=port))
                self.assertEqual(status, 400)
                self.assertIn("dst_port", body["error"])
                insert.assert_not_called()

    def test_json_body_must_be_an_object(self):
        for payload in (None, [], "invalid", 0):
            with self.subTest(payload=payload), patch(
                "src.routers.ignorelist.insert_ignorelist_entry"
            ) as insert:
                status, body = self.request(payload)
                self.assertEqual(status, 400)
                self.assertIn("error", body)
                insert.assert_not_called()

    def test_zero_is_persisted_and_matches_existing_and_future_flows(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "ignorelist-test.db"
            conn = sqlite3.connect(database)
            try:
                conn.executescript(
                    CONST_CREATE_IGNORELIST_SQL + CONST_CREATE_ALLFLOWS_SQL
                    + CONST_CREATE_ALERTS_SQL
                )
                flows = [
                    ("10.4.60.13", "10.4.20.17", 1000, 0, 1),
                    ("10.4.60.13", "10.4.20.17", 1000, 8, 1),
                    ("10.4.60.13", "10.4.20.17", 1000, 0, 6),
                    ("10.4.60.13", "10.4.20.18", 1000, 0, 1),
                ]
                conn.executemany(
                    "INSERT INTO allflows (src_ip, dst_ip, src_port, dst_port, protocol) "
                    "VALUES (?, ?, ?, ?, ?)", flows,
                )
                conn.executemany(
                    "INSERT INTO alerts (id, ip_address, flow) VALUES (?, ?, ?)",
                    [(str(index), flow[0], json.dumps(flow))
                     for index, flow in enumerate(flows)],
                )
                conn.commit()
                with patch.dict("src.database.core.TABLE_DB_MAP", {
                    name: str(database) for name in ("ignorelist", "allflows", "alerts")
                }):
                    status, _ = self.request(self.payload)
                    self.assertEqual(status, 200)
                    entries = get_ignorelist()
                    self.assertEqual(len(entries), 1)
                    self.assertEqual(entries[0][3:], (0, 1))
                    self.assertIn("DstPort:0_Protocol:1", entries[0][0])
                    status, body = self.request(None, method="GET")
                    self.assertEqual(status, 200)
                    self.assertEqual(body[0]["dst_port"], 0)
                    for index, flow in enumerate(flows):
                        record = dict(zip(
                            ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"), flow
                        ))
                        tag = tag_ignorelist(record, entries)
                        self.assertEqual(tag is not None, index == 0)
                        stored_tag = conn.execute(
                            "SELECT tags FROM allflows WHERE src_ip = ? AND dst_ip = ? "
                            "AND src_port = ? AND dst_port = ? AND protocol = ?", flow,
                        ).fetchone()[0]
                        self.assertEqual(bool(stored_tag), index == 0)
                    remaining = {row[0] for row in conn.execute("SELECT id FROM alerts")}
                    self.assertEqual(remaining, {"1", "2", "3"})
            finally:
                conn.close()


class StaleIgnorelistTests(unittest.TestCase):
    def setUp(self):
        for target in ("src.database.ignorelist.log_error", "src.routers.ignorelist.log_error"):
            logger_patch = patch(target)
            logger_patch.start()
            self.addCleanup(logger_patch.stop)

    def test_bulk_delete_uses_latest_exact_tag_and_deletes_null_last_seen(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as cleanup:
            flows_path = Path(directory) / "flows.db"
            flows = sqlite3.connect(flows_path)
            cleanup.callback(flows.close)
            flows.execute("CREATE TABLE allflows (tags TEXT, last_seen TEXT)")
            entries = sqlite3.connect(":memory:")
            cleanup.callback(entries.close)
            entries.execute("CREATE TABLE ignorelist (ignorelist_id TEXT PRIMARY KEY)")
            identifiers = [
                "old", "other_host", "recent", "boundary", "unseen", "unknown",
                "invalid", "prefix", "prefix_long", "mixed_unknown", "recent_unknown",
            ]
            entries.executemany("INSERT INTO ignorelist VALUES (?)", [(name,) for name in identifiers])
            for tag, modifier in [
                (" IgnoreList_old ;IgnoreList_other_host;unrelated", "-31 days"),
                ("IgnoreList_recent", "-40 days"),
                ("IgnoreList_recent", "-1 day"),
                ("IgnoreList_boundary", "-30 days"),
                ("IgnoreList_prefix", "-31 days"),
                ("IgnoreList_prefix_long", "-1 day"),
                ("IgnoreList_unseen_long", "-1 day"),
                ("IgnoreList_mixed_unknown", "-31 days"),
                ("IgnoreList_recent_unknown", "-1 day"),
            ]:
                flows.execute(
                    "INSERT INTO allflows VALUES (?, datetime('now', 'localtime', ?))",
                    (tag, modifier),
                )
            flows.executemany("INSERT INTO allflows VALUES (?, ?)", [
                ("IgnoreList_unknown", None),
                ("IgnoreList_unknown", None),
                ("IgnoreList_invalid", "invalid"),
                ("IgnoreList_mixed_unknown", None),
                ("IgnoreList_recent_unknown", None),
                (None, None),
                ("", None),
            ])
            flows.commit()
            flows.close()
            entries.commit()
            with patch("src.database.ignorelist.connect_to_db", return_value=entries), patch(
                "src.database.ignorelist.disconnect_from_db"
            ), patch.dict("src.database.ignorelist.TABLE_DB_MAP", {"allflows": str(flows_path)}):
                self.assertEqual(delete_stale_ignorelist_entries(), 5)
            remaining = {row[0] for row in entries.execute("SELECT ignorelist_id FROM ignorelist")}
            self.assertEqual(remaining, set(identifiers) - {"old", "other_host", "prefix", "unseen", "unknown"})
            entries.close()

    def test_bulk_delete_purges_unseen_entries_without_waiting_30_days(self):
        with tempfile.TemporaryDirectory() as directory:
            flows_path = Path(directory) / "flows.db"
            flows = sqlite3.connect(flows_path)
            flows.execute("CREATE TABLE allflows (tags TEXT, last_seen TEXT)")
            flows.close()
            entries = sqlite3.connect(":memory:")
            try:
                entries.execute("CREATE TABLE ignorelist (ignorelist_id TEXT PRIMARY KEY)")
                entries.execute("INSERT INTO ignorelist VALUES ('unseen')")
                entries.commit()
                with patch("src.database.ignorelist.connect_to_db", return_value=entries), patch(
                    "src.database.ignorelist.disconnect_from_db"
                ), patch.dict("src.database.ignorelist.TABLE_DB_MAP", {"allflows": str(flows_path)}):
                    self.assertEqual(delete_stale_ignorelist_entries(), 1)
                self.assertEqual(
                    entries.execute("SELECT COUNT(*) FROM ignorelist").fetchone()[0],
                    0,
                )
            finally:
                entries.close()

    def test_missing_flow_database_does_not_delete_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            entries = sqlite3.connect(":memory:")
            self.addCleanup(entries.close)
            entries.execute("CREATE TABLE ignorelist (ignorelist_id TEXT)")
            entries.execute("INSERT INTO ignorelist VALUES ('keep')")
            entries.commit()
            missing_path = Path(directory) / "missing.db"
            with patch("src.database.ignorelist.connect_to_db", return_value=entries), patch(
                "src.database.ignorelist.disconnect_from_db"
            ), patch.dict("src.database.ignorelist.TABLE_DB_MAP", {"allflows": str(missing_path)}):
                with self.assertRaises(sqlite3.Error):
                    delete_stale_ignorelist_entries()
            self.assertEqual(entries.execute("SELECT COUNT(*) FROM ignorelist").fetchone()[0], 1)
            self.assertFalse(missing_path.exists())
            entries.close()

    def test_route_returns_count_and_reports_failure(self):
        app = Bottle()
        setup_ignorelist_routes(app)
        for result, error, expected_status in [(4, None, "200"), (0, None, "200"), (None, RuntimeError("failed"), "500")]:
            with self.subTest(result=result, error=error):
                statuses = []
                with patch("src.routers.ignorelist.delete_stale_ignorelist_entries", return_value=result, side_effect=error) as cleanup:
                    body = b"".join(app({
                        "REQUEST_METHOD": "DELETE",
                        "PATH_INFO": "/api/ignorelist/stale",
                        "SERVER_NAME": "localhost",
                        "SERVER_PORT": "80",
                        "SERVER_PROTOCOL": "HTTP/1.1",
                        "wsgi.url_scheme": "http",
                        "wsgi.input": BytesIO(),
                        "wsgi.errors": BytesIO(),
                    }, lambda status, headers, exc_info=None: statuses.append(status)))
                cleanup.assert_called_once_with()
                self.assertTrue(statuses[0].startswith(expected_status))
                payload = json.loads(body)
                if error:
                    self.assertIn("error", payload)
                else:
                    self.assertEqual(payload["deleted_count"], result)