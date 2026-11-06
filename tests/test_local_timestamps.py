import json
import sqlite3
import unittest
from io import BytesIO
from unittest.mock import patch

from bottle import Bottle

from src.const import (CONST_CREATE_ACTIONS_SQL, CONST_CREATE_CONFIG_SQL,
                       CONST_CREATE_CUSTOMTAGS_SQL)
from src.database.actions import insert_action
from src.routers.actions import setup_actions_routes


class LocalTimestampTests(unittest.TestCase):
    LOCAL_TIME = "2026-11-07 07:26:29"
    UTC_TIME = "2026-11-06 22:26:29"

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.create_function(
            "datetime", -1,
            lambda *args: self.LOCAL_TIME
            if args == ("now", "localtime") else self.UTC_TIME,
        )
        self.conn.create_function("current_timestamp", 0, lambda: self.UTC_TIME)
        for schema in (
            CONST_CREATE_ACTIONS_SQL,
            CONST_CREATE_CONFIG_SQL,
            CONST_CREATE_CUSTOMTAGS_SQL,
        ):
            self.conn.executescript(schema)
        for target, kwargs in (
            ("src.database.actions.connect_to_db", {"return_value": self.conn}),
            ("src.database.actions.disconnect_from_db", {}),
            ("src.database.actions.log_info", {}),
            ("src.database.core.log_info", {}),
            ("src.database.core.insert_dbperformance", {}),
        ):
            patcher = patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_new_action_is_stored_in_local_time(self):
        self.assertTrue(insert_action("New host detected"))
        row = self.conn.execute(
            "SELECT action_text, acknowledged, insert_date FROM actions"
        ).fetchone()
        self.assertEqual(row, ("New host detected", 0, self.LOCAL_TIME))

    def test_timestamp_defaults_use_local_time(self):
        self.conn.execute("INSERT INTO actions (action_text) VALUES ('Action')")
        self.conn.execute("INSERT INTO configuration (key, value) VALUES ('test', 1)")
        self.conn.execute("INSERT INTO customtags (tag_id) VALUES ('tag')")
        for table, columns in (
            ("actions", ("insert_date",)),
            ("configuration", ("last_changed",)),
            ("customtags", ("added", "insert_date")),
        ):
            with self.subTest(table=table):
                row = self.conn.execute(
                    f"SELECT {', '.join(columns)} FROM {table}"
                ).fetchone()
                self.assertEqual(row, (self.LOCAL_TIME,) * len(columns))

    def test_actions_api_preserves_existing_times_and_returns_new_local_time(self):
        self.conn.execute(
            "INSERT INTO actions (action_text, insert_date) VALUES (?, ?)",
            ("Existing action", self.UTC_TIME),
        )
        self.assertTrue(insert_action("New action"))
        app = Bottle()
        setup_actions_routes(app)
        statuses = []
        body = b"".join(app({
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/actions",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "wsgi.url_scheme": "http",
            "wsgi.input": BytesIO(),
            "wsgi.errors": BytesIO(),
        }, lambda status, headers, exc_info=None: statuses.append(status)))
        self.assertTrue(statuses[0].startswith("200"))
        actions = {row["action_text"]: row for row in json.loads(body)}
        self.assertEqual(actions["Existing action"]["insert_date"], self.UTC_TIME)
        self.assertEqual(actions["New action"]["insert_date"], self.LOCAL_TIME)
        self.assertEqual(
            set(actions["New action"]),
            {"action_id", "action_text", "acknowledged", "insert_date"},
        )
