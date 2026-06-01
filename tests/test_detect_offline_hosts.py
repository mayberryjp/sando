import unittest
from unittest.mock import patch

from src.detect.detect_offline_hosts import detect_offline_hosts


class OfflineHostDetectionTests(unittest.TestCase):
    def test_detect_offline_hosts_alerts_only_enabled_hosts_without_recent_traffic(self):
        localhosts = [
            {"ip_address": "192.0.2.10", "alert_if_offline": 1},
            {"ip_address": "192.0.2.11", "alert_if_offline": 1},
            {"ip_address": "192.0.2.12", "alert_if_offline": 0},
            {"mac_address": "AA:BB:CC:DD:EE:FF", "alert_if_offline": 1},
        ]
        traffic_status = {
            "192.0.2.10": True,
            "192.0.2.11": False,
            "192.0.2.12": False,
        }

        with patch(
            "src.detect.detect_offline_hosts.get_localhosts_all",
            return_value=localhosts,
        ), patch(
            "src.detect.detect_offline_hosts.get_all_ips_traffic_status",
            return_value=traffic_status,
        ), patch(
            "src.detect.detect_offline_hosts.handle_alert"
        ) as mock_handle_alert:
            detect_offline_hosts({"OfflineHostDetection": 1})

        mock_handle_alert.assert_called_once()
        args = mock_handle_alert.call_args.args
        self.assertEqual(args[1], "OfflineHostDetection")
        self.assertEqual(args[3], "192.0.2.11")
        self.assertEqual(args[4], {"ip_address": "192.0.2.11", "alert_if_offline": 1})
        self.assertEqual(args[8], "192.0.2.11_OfflineHostDetection")


if __name__ == "__main__":
    unittest.main()
