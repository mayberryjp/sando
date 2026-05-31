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

Required final artifact:
- Before finishing, create or update .agent/change-summaries/issue-41-backend.md.
- This file will be consumed by a later documentation/release agent.
- The file is required even if no code changes were made.
- Base it only on verified repository changes. Do not invent behavior.
- Use exactly this format:

## Agent Change Summary

### What changed
- ...

### User-facing impact
- ...

### Files changed
- ...

### README impact
- ...

### Announcement impact
- ...

### Testing / validation
- ...

### Open questions
- ...

Definition of done:
- The requested change is implemented.
- Relevant tests pass, or you clearly document why tests could not be run.
- .agent/change-summary.md exists and follows the required format.
- The change is ready for human review.

Full GitHub issue context follows.

# GitHub Issue #41

URL: https://github.com/mayberryjp/sando/issues/41

Title: New detection type for a device being offline

Labels: sando_backend_agent_delegated

Author: @mayberryjp

## Original Issue Body

I want to introduce a new detection type for a host being offline. This detection type is per host so it should be a new parameter on localhost.

Because it's a new parameter on localhost it will need a database schema update in const and a migration code to database schema version 21.

When adding a new host the parameter for alert_if_offline should be true/enabled.

We will need API routes to flip just this parameter 

Also any existing localhost modification API will need to be updated to include this parameter.

A new file for this detection should be added and called from the main detection processor.

The primary trigger for the detection should be if a host has no trafficstats recently. There may already be a function to determine this. The detection can be called DetectOfflineHosts

This alert should be enabled by default at install in const.py







## Issue Comments / Conversation

### Comment by @mayberryjp at 2026-05-31T05:49:37Z

Codex implementation notes

Expected behavior:
- Add per-host offline alerting controlled by a new `localhosts.alert_if_offline` field, default enabled for new and existing hosts.
- Add schema version 21: bump `CONST_DATABASE_SCHEMA_VERSION` in `src/const.py`, add `alert_if_offline INTEGER DEFAULT 1` to `CONST_CREATE_LOCALHOSTS_SQL`, and add a migration in `src/database/common.py` for existing installs.
- Add API support to flip only this parameter, and update existing localhost modification/read paths so the field is visible and can be changed where appropriate.
- Add a new detection implementation, probably `src/detect/detect_offline_hosts.py`, and call it from `src/utils/detections.py`.

Likely files/areas:
- `src/const.py`: schema version, localhost table definition, and likely an install config entry such as `OfflineHostDetection` defaulting enabled if the detection pipeline should have a global gate.
- `src/database/common.py`: migration from schema <21 that adds `alert_if_offline` idempotently.
- `src/database/localhosts.py`: include the new column in `get_localhost_by_ip()` / `get_localhosts_all()` selects and add an `update_localhost_alert_if_offline(identifier, enabled)` helper similar to `update_localhost_alerts_enabled()`.
- `src/routers/localhosts.py`: expose the field in GET responses, update the existing modification endpoint if it accepts localhost fields, and add a dedicated route similar to `/api/localhosts/<ip_address>/alerts-enabled` for flipping only `alert_if_offline`.
- `src/database/trafficstats.py`: `get_all_ips_traffic_status()` already determines whether localhosts had traffic in the last 100 hours; it may be the existing function referenced by the issue.
- `src/utils/detections.py`: import/call `detect_offline_hosts` from the main processor.
- `src/notifications/core.py`: no change expected if the new detection uses `handle_alert()` consistently.

Detection behavior and edge cases:
- Inference: detect hosts where `alert_if_offline == 1` and recent traffic status is false according to `trafficstats`; use a stable alert id like `<ip>_OfflineHostDetection` to avoid duplicate alert rows.
- Skip or carefully handle host records without an `ip_address` (MAC-only DHCP records), because `trafficstats` is keyed by IP.
- Consider suppressing alerts for newly created hosts until they are older than the “recent traffic” window, otherwise brand-new hosts with no stats may alert immediately. This is a product decision; do not silently invent it without checking if tests clarify intent.
- Existing `alerts_enabled` still gates notification delivery in `handle_alert`; `alert_if_offline` should be the per-host opt-in/out for this specific detection.

Acceptance criteria:
- Fresh database schema includes `alert_if_offline` defaulting to 1.
- Existing databases migrate to schema 21 and backfill existing localhost rows to enabled/default 1.
- New hosts inserted through `insert_localhost_basic()` and MAC-only inserts inherit `alert_if_offline = 1` through the schema default.
- API can update only `alert_if_offline` for a host and returns the field in host/list responses.
- Detection creates an offline-host alert only for hosts with the flag enabled and no recent trafficstats.

Test suggestions:
- Migration test or local sqlite smoke test: schema 20 localhosts table upgrades and existing rows get `alert_if_offline` default 1.
- Database helper test for toggling `alert_if_offline` by IP/MAC and for missing host behavior.
- Detection test with one active host, one inactive enabled host, one inactive disabled host, and one MAC-only host.
- API smoke tests for the new toggle route and existing localhost GET/list output.

Uncertainty:
- The issue says “This alert should be enabled by default at install in const.py.” I infer that means both the per-host column default should be 1 and, if using a global detection config key, that config should default enabled. Confirm if global default-on detection is intended.

