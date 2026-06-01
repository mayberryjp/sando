Implemented issue #33.

Changed [docker_config_examples/Dockerfile](/tmp/runner/work/sando/sando/docker_config_examples/Dockerfile:1) to use `python:3.14.5-alpine` instead of `python:3.14.2-alpine`.

Added required agent summaries:
- [.agent/change-summaries/issue-33-backend.md](/tmp/runner/work/sando/sando/.agent/change-summaries/issue-33-backend.md:1)
- [.agent/change-summary.md](/tmp/runner/work/sando/sando/.agent/change-summary.md:1)

Validation:
- `docker manifest inspect python:3.14.5-alpine` passed.
- Python tests could not run: `python` is missing, and `python3` exists but `pytest` is not installed.

Note: `.agent/issue.md` was already modified before my changes; I left it untouched.