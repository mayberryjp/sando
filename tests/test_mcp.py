import unittest
import sys
import types
from importlib import import_module
from unittest.mock import patch


def import_mcp_module():
    try:
        return import_module("src.processes.mcp")
    except ModuleNotFoundError as exc:
        if exc.name != "bottle":
            raise

    class FakeBottle:
        def route(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

    bottle = types.ModuleType("bottle")
    bottle.Bottle = FakeBottle
    bottle.request = types.SimpleNamespace(json=None)
    bottle.response = types.SimpleNamespace(content_type=None)
    bottle.run = lambda *args, **kwargs: None
    sys.modules["bottle"] = bottle
    sys.modules.pop("src.processes.mcp", None)
    return import_module("src.processes.mcp")


mcp = import_mcp_module()


class McpToolTests(unittest.TestCase):
    def test_list_hosts_tool_is_registered(self):
        self.assertIn("list_hosts", mcp.TOOLS)

        tool = mcp.TOOLS["list_hosts"]
        self.assertEqual(tool["name"], "list_hosts")
        self.assertEqual(
            tool["inputSchema"],
            {"type": "object", "properties": {}},
        )

    def test_list_hosts_returns_all_localhosts_from_database_helper(self):
        hosts = [
            {
                "ip_address": "192.0.2.10",
                "mac_address": "00:11:22:33:44:55",
                "dhcp_hostname": "test-host",
                "whitelisted": 0,
            }
        ]

        with patch("src.processes.mcp.get_localhosts_all", return_value=hosts) as helper:
            result = mcp.TOOLS["list_hosts"]["function"]({})

        helper.assert_called_once_with()
        self.assertEqual(result, hosts)


if __name__ == "__main__":
    unittest.main()
