## Agent Change Summary

### What changed
- Updated the example Dockerfile base image from `python:3.14.2-alpine` to `python:3.14.5-alpine`.

### User-facing impact
- New containers built from `docker_config_examples/Dockerfile` will use the newer Python 3.14 Alpine base image.

### Files changed
- `docker_config_examples/Dockerfile`
- `.agent/change-summaries/issue-33-backend.md`
- `.agent/change-summary.md`

### README impact
- No README changes required.

### Announcement impact
- No announcement impact identified.

### Testing / validation
- Ran `docker manifest inspect python:3.14.5-alpine` successfully.
- Attempted `python -m pytest tests/test_notifications_core.py tests/test_discord_notifications.py`, but `python` was not installed on PATH.
- Attempted `python3 -m pytest tests/test_notifications_core.py tests/test_discord_notifications.py`, but `pytest` was not installed in the environment.

### Open questions
- None.
