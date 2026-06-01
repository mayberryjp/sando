import json

from src.database.configuration import get_local_networks


def test_get_local_networks_preserves_metadata_and_normalizes_ip_version():
    config = {
        "LocalNetworks": json.dumps(
            [
                {
                    "cidr": "192.168.1.0/24",
                    "router": "192.168.1.1",
                    "site": "home",
                },
                {
                    "cidr": "2001:db8::/64",
                    "ip_version": "IPv6",
                    "router": "2001:db8::1",
                },
                {"cidr": "10.0.0.0/8", "ip_version": "4"},
            ]
        )
    }

    assert get_local_networks(config) == [
        {
            "cidr": "192.168.1.0/24",
            "router": "192.168.1.1",
            "site": "home",
            "ip_version": 4,
        },
        {
            "cidr": "2001:db8::/64",
            "ip_version": 6,
            "router": "2001:db8::1",
        },
        {"cidr": "10.0.0.0/8", "ip_version": 4},
    ]


def test_get_local_networks_handles_missing_empty_and_malformed_config():
    assert get_local_networks({}) == []
    assert get_local_networks({"LocalNetworks": "[]"}) == []
    assert get_local_networks({"LocalNetworks": "not-json"}) == []


def test_get_local_networks_skips_entries_without_cidr():
    config = {
        "LocalNetworks": json.dumps(
            [
                {"router": "192.168.1.1", "ip_version": 4},
                "not-a-scope",
                {"cidr": "2001:db8::/64", "ip_version": 6},
            ]
        )
    }

    assert get_local_networks(config) == [{"cidr": "2001:db8::/64", "ip_version": 6}]
