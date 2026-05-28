import unittest
from unittest.mock import patch

from src.notifications.core import handle_alert


class CoreNotificationTests(unittest.TestCase):
    def test_handle_alert_sends_discord_for_new_alerts(self):
        with patch(
            "src.notifications.core.get_localhost_by_ip", return_value=None
        ), patch(
            "src.notifications.core.log_alert_to_db", return_value="insert"
        ), patch(
            "src.notifications.core.send_telegram_message"
        ) as mock_telegram, patch(
            "src.notifications.core.send_discord_message"
        ) as mock_discord:
            result = handle_alert(
                {"NewOutboundDetection": 2},
                "NewOutboundDetection",
                "alert message",
                "192.0.2.10",
                {"flow": "data"},
                "category",
                "enrichment_1",
                "enrichment_2",
                "hash",
            )

        self.assertEqual(result, "insert")
        mock_telegram.assert_called_once_with("alert message", {"flow": "data"})
        mock_discord.assert_called_once_with("alert message", {"flow": "data"})

    def test_handle_alert_sends_discord_for_level_three_updates(self):
        with patch(
            "src.notifications.core.get_localhost_by_ip", return_value=None
        ), patch(
            "src.notifications.core.log_alert_to_db", return_value="update"
        ), patch(
            "src.notifications.core.send_telegram_message"
        ) as mock_telegram, patch(
            "src.notifications.core.send_discord_message"
        ) as mock_discord:
            result = handle_alert(
                {"NewOutboundDetection": 3},
                "NewOutboundDetection",
                "alert message",
                "192.0.2.10",
                {"flow": "data"},
                "category",
                "enrichment_1",
                "enrichment_2",
                "hash",
            )

        self.assertEqual(result, "update")
        mock_telegram.assert_called_once_with("alert message", {"flow": "data"})
        mock_discord.assert_called_once_with("alert message", {"flow": "data"})

    def test_handle_alert_does_not_send_update_notifications_at_level_two(self):
        with patch(
            "src.notifications.core.get_localhost_by_ip", return_value=None
        ), patch(
            "src.notifications.core.log_alert_to_db", return_value="update"
        ), patch(
            "src.notifications.core.send_telegram_message"
        ) as mock_telegram, patch(
            "src.notifications.core.send_discord_message"
        ) as mock_discord:
            result = handle_alert(
                {"NewOutboundDetection": 2},
                "NewOutboundDetection",
                "alert message",
                "192.0.2.10",
                {"flow": "data"},
                "category",
                "enrichment_1",
                "enrichment_2",
                "hash",
            )

        self.assertEqual(result, "update")
        mock_telegram.assert_not_called()
        mock_discord.assert_not_called()


if __name__ == "__main__":
    unittest.main()
