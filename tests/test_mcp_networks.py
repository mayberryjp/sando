import json

from src.processes import mcp


def test_get_networks_tool_is_registered():
    assert "get_networks" in mcp.TOOLS


def test_get_networks_returns_configured_networks(monkeypatch):
    monkeypatch.setattr(
        mcp,
        "get_all_configuration",
        lambda: [
            {
                "key": "LocalNetworks",
                "value": json.dumps(
                    [
                        {"cidr": "192.168.1.0/24"},
                        {"cidr": "2001:db8::/64", "ip_version": 6},
                    ]
                ),
                "last_changed": "2026-05-31 00:00:00",
            }
        ],
    )

    assert mcp.TOOLS["get_networks"]["function"]({}) == [
        {"cidr": "192.168.1.0/24", "ip_version": 4},
        {"cidr": "2001:db8::/64", "ip_version": 6},
    ]
