Implemented Discord notifications.

Changed:
- Added `DiscordWebhookUrl` and `DiscordEnabled` defaults in [src/const.py](/tmp/runner/work/sando/sando/src/const.py:330).
- Added `send_discord_message()` and `send_test_discord_message()` in [src/notifications/discord.py](/tmp/runner/work/sando/sando/src/notifications/discord.py:30).
- Wired Discord alert sends into [src/notifications/core.py](/tmp/runner/work/sando/sando/src/notifications/core.py:78) and made Telegram-specific log messages generic.
- Added startup Discord test notification in [src/processes/processor.py](/tmp/runner/work/sando/sando/src/processes/processor.py:33).
- Sanitized `DiscordWebhookUrl` during config upload in [src/utils/client.py](/tmp/runner/work/sando/sando/src/utils/client.py:249).
- Added unit tests and unignored Python test files in `.gitignore`.

Verification:
- `python3 -m unittest discover -s tests` passed: 8 tests.
- `python3 -m compileall src tests` passed.

Note: existing untracked `.agent/issue.md` was left untouched.