You are working in the mayberryjp/sando repository.

Implement the requested backend change from this GitHub issue.

Important:
- You must inspect the repository and make source code changes unless the feature is already implemented.
- Do not only summarize the issue.
- Do not stop after analysis.
- If no code change is needed, explain exactly which existing files already implement the behavior.
- Make the smallest reasonable code change.
- Prefer backend/API/server code changes.
- Do not edit unrelated files.
- Do not change secrets, credentials, workflow permissions, runner config, or Docker runner configuration.
- Do not edit files under .github/workflows unless the issue explicitly asks for workflow changes.
- Run relevant tests if available.
- Leave the repo in a commit-ready state.

Definition of done:
- The requested change is implemented.
- Relevant tests pass, or you clearly document why tests could not be run.
- The change is ready for human review.

Full GitHub issue context follows.

# GitHub Issue #11

URL: https://github.com/mayberryjp/sando/issues/11

Title: Support Discord notifications mechanism

Labels: sando_backend_agent_delegated

Author: @mayberryjp

## Original Issue Body

Scope of work
* Create new configuration variable for DiscordWebhookUrl with a default empty value
* In default config in const.py, add empty string variables for DiscordWebhookUrl and DiscordEnabled
* Create new configuration variable for DiscordEnabled
* At startup, send a discord test notification with the version similar to the telegram notification
* In the notification, if DiscordWebhookUrl and DiscordEnabled, send notifications
* Send notifications using the Discord webhook approach which is the easiest and fastest way to do discord notifications

## Issue Comments / Conversation

### Comment by @mayberryjp at 2026-05-26T05:48:22Z

## Codex implementation notes

Expected behavior from the issue:
- Add `DiscordWebhookUrl` and `DiscordEnabled` configuration keys, defaulting to empty string / disabled, alongside the existing Telegram configuration in `src/const.py` `CONST_INSTALL_CONFIGS`.
- The issue also says to add `DiscordEnabledOff` as an empty string in default config. That name looks potentially accidental or legacy; implement it only if the product intent is to preserve that exact key, and otherwise clarify before treating it as a functional flag.
- At processor startup, send a Discord online/test notification with the version, mirroring `send_test_telegram_message()` in `src/notifications/telegram.py` and its call in `src/processes/processor.py`.
- When alert notifications are sent, Discord should be gated by both `DiscordWebhookUrl` being non-empty and `DiscordEnabled` being truthy/enabled.

Likely files/areas to inspect:
- `src/const.py`: add install defaults near `TelegramBotToken`, `TelegramChatId`, and `TelegramEnabled`.
- `src/notifications/telegram.py`: current pattern for startup and alert sends; a parallel `discord.py` module would keep concerns separate.
- `src/notifications/core.py`: currently calls `send_telegram_message()` for new/updated alerts; add Discord send behavior in the same insert/update branches.
- `src/processes/processor.py`: imports/calls the startup Telegram test sender; add the Discord startup sender here.
- `src/utils/client.py`: if cloud configuration uploads include the new settings, sanitize `DiscordWebhookUrl` like the Telegram token/chat values.

Edge cases:
- Missing webhook URL, disabled flag, or malformed webhook should not crash processing; log and continue, matching Telegram's defensive behavior.
- Discord webhooks commonly return HTTP 204 on success, not only 200.
- Avoid logging the full webhook URL in errors because it is a secret.
- Preserve existing Telegram behavior; Discord should be additive.

Acceptance criteria:
- Fresh/default config contains the new Discord keys with disabled/empty defaults.
- With Discord disabled or no webhook configured, startup and alerts skip Discord sends without exceptions.
- With Discord enabled and webhook configured, startup sends an online/version message and alert paths send Discord notifications for the same new/update cases that currently trigger Telegram.
- Existing Telegram tests/behavior remain unchanged.

Test suggestions:
- Unit test the Discord sender using mocked `requests.post` for success (`204` and/or `200`), non-2xx responses, missing config, and exceptions.
- Unit/integration-style test `handle_alert()` with mocked notification functions to verify Discord is called only for insert/update levels matching Telegram behavior.
- Verify configuration upload sanitization if the new webhook key is included in exported config.

Uncertainty:
- `DiscordEnabledOff` is listed in the issue but does not have an obvious existing pattern. Treating it as a required config key is a direct reading of the issue; treating it as a typo is an inference and should be confirmed before omitting it.


---

### Comment by @mayberryjp at 2026-05-26T06:02:41Z

DiscordEnabled is the correct flag name, not DiscordEnabledOff is. It's the flag for enabling/disabling Discord. Default is off or 0 as a string value. There should be a dedicated test function. 

Send the test message only if Discord is enabled and webhook URL is present. Fail cleanly if the send doesn't work. 

Any log message in core.py def handle_alert that references Telegram explicitly should be made generic. This same function is where send_telegram_message is called and send_discord_message can be referenced. 

there should be a new send_discord_message function









