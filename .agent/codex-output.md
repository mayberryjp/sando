Implemented issue #41 backend changes.

Changed:
- Bumped schema to `21` and added `localhosts.alert_if_offline INTEGER DEFAULT 1`.
- Added schema migration for existing databases.
- Added `OfflineHostDetection` default enabled in install config.
- Added DB helper and API support for `alert_if_offline`.
- Added `PUT /api/localhosts/<ip_address>/alert-if-offline`.
- Added offline host detector and wired it into the detection processor.
- Created required summary: `.agent/change-summaries/issue-41-backend.md`.

Validation:
- `python3 -m compileall src` passed.
- Scoped `git diff --check` for my changed files passed.
- `python3 -m pytest` could not run because `pytest` is not installed.
- Runtime smoke test could not run because `pytz` is not installed.
- Full `git diff --check` is blocked by pre-existing trailing whitespace in `.agent/issue.md`, which I did not edit.

Note: `.agent/issue.md` was already modified before my work and remains untouched.