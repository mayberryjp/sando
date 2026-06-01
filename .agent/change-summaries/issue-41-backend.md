## Agent Change Summary

### Agent
- Backend

### GitHub issue
- #41

### What changed
- Added schema version 21 with `localhosts.alert_if_offline INTEGER DEFAULT 1` in the fresh database schema.
- Added an idempotent schema 20 to 21 migration that adds `alert_if_offline` to existing `localhosts` tables and defaults existing rows to enabled.
- Added `OfflineHostDetection` to install defaults as enabled.
- Added database read/update support for `alert_if_offline` on localhost records.
- Added `PUT /api/localhosts/<ip_address>/alert-if-offline` to update only the offline alert flag.
- Updated existing localhost GET/list and modification paths to include or update `alert_if_offline`.
- Added `src/detect/detect_offline_hosts.py` and wired it into the main detection processor.
- Added focused tests for the schema migration, localhost toggle helper, and offline host detection behavior.

### User-facing impact
- Hosts now have a per-host `alert_if_offline` setting that defaults enabled for new and migrated hosts.
- API clients can read the offline alert flag from localhost responses and toggle it independently.
- The detection processor can create an `Offline Host Detected` alert for enabled hosts that have no recent trafficstats.

### Files changed
- `src/const.py`
- `src/database/common.py`
- `src/database/localhosts.py`
- `src/routers/localhosts.py`
- `src/detect/detect_offline_hosts.py`
- `src/utils/detections.py`
- `tests/test_localhosts.py`
- `tests/test_detect_offline_hosts.py`
- `.agent/change-summaries/issue-41-backend.md`

### README impact
- README may need an API/detection settings update for the new `alert_if_offline` field and `/api/localhosts/<ip_address>/alert-if-offline` route.

### Announcement impact
- Announce a new default-enabled offline host detection with per-host opt-out.

### Testing / validation
- `python3 -m py_compile src/const.py src/database/common.py src/database/localhosts.py src/routers/localhosts.py src/detect/detect_offline_hosts.py src/utils/detections.py tests/test_localhosts.py tests/test_detect_offline_hosts.py` passed.
- `python3 -m unittest tests.test_localhosts tests.test_detect_offline_hosts tests.test_notifications_core tests.test_mcp` passed.
- `python3 -m unittest discover tests` passed.

### Open questions
- None.
