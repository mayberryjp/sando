import unittest
from unittest.mock import Mock, patch

from src.const import VERSION
from src.notifications.discord import send_discord_message, send_test_discord_message


class DiscordNotificationTests(unittest.TestCase):
    def test_send_discord_message_skips_when_disabled(self):
        with patch(
            "src.notifications.discord.get_config_settings",
            return_value={
                "DiscordWebhookUrl": "https://discord.example/webhook",
                "DiscordEnabled": "0",
            },
        ), patch("src.notifications.discord.requests.post") as mock_post:
            send_discord_message("alert", {})

        mock_post.assert_not_called()

    def test_send_discord_message_skips_without_webhook(self):
        with patch(
            "src.notifications.discord.get_config_settings",
            return_value={"DiscordWebhookUrl": "", "DiscordEnabled": "1"},
        ), patch("src.notifications.discord.requests.post") as mock_post:
            send_discord_message("alert", {})

        mock_post.assert_not_called()

    def test_send_discord_message_accepts_204_success(self):
        response = Mock(status_code=204, text="")
        with patch(
            "src.notifications.discord.get_config_settings",
            return_value={
                "DiscordWebhookUrl": "https://discord.example/webhook",
                "DiscordEnabled": "1",
            },
        ), patch(
            "src.notifications.discord.requests.post", return_value=response
        ) as mock_post:
            send_discord_message("alert", {})

        mock_post.assert_called_once()
        self.assertEqual(
            mock_post.call_args.kwargs["json"]["content"],
            "SANDO Security Alert - TESTPPE\n\nalert",
        )
        self.assertEqual(mock_post.call_args.kwargs["timeout"], 10)

    def test_send_discord_message_logs_non_success(self):
        response = Mock(status_code=500, text="bad")
        with patch(
            "src.notifications.discord.get_config_settings",
            return_value={
                "DiscordWebhookUrl": "https://discord.example/webhook",
                "DiscordEnabled": "1",
            },
        ), patch("src.notifications.discord.requests.post", return_value=response), patch(
            "src.notifications.discord.log_error"
        ) as mock_log_error:
            send_discord_message("alert", {})

        mock_log_error.assert_called_once()

    def test_send_test_discord_message_sends_version_message(self):
        response = Mock(status_code=200, text="")
        with patch(
            "src.notifications.discord.get_config_settings",
            return_value={
                "DiscordWebhookUrl": "https://discord.example/webhook",
                "DiscordEnabled": "true",
            },
        ), patch(
            "src.notifications.discord.requests.post", return_value=response
        ) as mock_post:
            send_test_discord_message()

        self.assertEqual(
            mock_post.call_args.kwargs["json"]["content"],
            f"SANDO is online - running version {VERSION} at TESTPPE.",
        )
        self.assertEqual(mock_post.call_args.kwargs["timeout"], 10)


if __name__ == "__main__":
    unittest.main()
