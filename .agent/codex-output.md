Implemented issue #42.

Changed:
- Added MCP tool `list_hosts` in [src/processes/mcp.py](/tmp/runner/work/sando/sando/src/processes/mcp.py), registered through the existing `mcp_tool` path.
- `list_hosts` delegates directly to `get_localhosts_all()`.
- Updated [src/database/localhosts.py](/tmp/runner/work/sando/sando/src/database/localhosts.py) so `get_localhosts_all()` includes the existing `last_seen` column.
- Added focused tests in [tests/test_mcp.py](/tmp/runner/work/sando/sando/tests/test_mcp.py) and [tests/test_localhosts.py](/tmp/runner/work/sando/sando/tests/test_localhosts.py).
- Created the required summary at [.agent/change-summaries/issue-42-backend.md](/tmp/runner/work/sando/sando/.agent/change-summaries/issue-42-backend.md).

Validation:
- `python3 -m py_compile src/processes/mcp.py src/database/localhosts.py tests/test_mcp.py tests/test_localhosts.py` passed.
- `python3 -m unittest tests.test_mcp tests.test_localhosts` passed.
- `python3 -m unittest discover tests` was attempted but fails because this environment is missing the unrelated `requests` dependency.
- `python3 -m pytest tests/test_mcp.py` was attempted but `pytest` is not installed.

Note: `.agent/issue.md` was already modified in the worktree and I left it untouched.