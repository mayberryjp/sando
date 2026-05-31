## Agent Change Summary

### What changed
- Added `localhosts.alert_if_offline` with default enabled behavior in the fresh schema and schema version 21 migration.
- Added an `OfflineHostDetection` install config default set to enabled.
- Added database, API, and detection processor support for per-host offline alerting.
- Added `src/detect/detect_offline_hosts.py`, which alerts for hosts with offline alerting enabled and no recent trafficstats entry.

### User-facing impact
- Localhost API responses now include `alert_if_offline`.
- Users can update only offline alerting for a host via `PUT /api/localhosts/<ip_address>/alert-if-offline`.
- Existing localhost update requests can include `alert_if_offline`.
- Offline host alerts are enabled by default for new and migrated hosts.

### Files changed
- `src/const.py`
- `src/database/common.py`
- `src/database/localhosts.py`
- `src/routers/localhosts.py`
- `src/detect/detect_offline_hosts.py`
- `src/utils/detections.py`
- `.agent/change-summaries/issue-41-backend.md`

### README impact
- README may need API documentation for the new `alert_if_offline` field and toggle route.

### Announcement impact
- Announce that Sando can now detect offline local hosts, with per-host opt-out through `alert_if_offline`.

### Testing / validation
- `python3 -m compileall src` passed.
- `python3 -m pytest` could not run because `pytest` is not installed in the environment.
- A targeted runtime smoke test could not run because dependency `pytz` is not installed in the environment.
- `git diff --check` is blocked by pre-existing trailing whitespace in `.agent/issue.md`, which was not modified for this change.

### Open questions
- None.
