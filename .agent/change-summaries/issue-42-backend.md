## Agent Change Summary

### What changed
- Added a new MCP tool named `list_hosts`.
- The tool returns the result of the existing `get_localhosts_all()` database helper without duplicating SQL.
- Updated `get_localhosts_all()` to include the existing `last_seen` localhost column in its returned dictionaries.
- Updated the MCP module's available tools documentation to include `list_hosts`.
- Added focused unit coverage for `list_hosts` registration and helper delegation.

### User-facing impact
- MCP clients can now call `list_hosts` to retrieve all known localhost records with the fields returned by `get_localhosts_all()`.
- If no hosts are known, the tool returns the helper's empty list result.

### Files changed
- `src/processes/mcp.py`
- `src/database/localhosts.py`
- `tests/test_localhosts.py`
- `tests/test_mcp.py`
- `.agent/change-summaries/issue-42-backend.md`

### README impact
- No README update was made.

### Announcement impact
- Announce that the MCP server now exposes a `list_hosts` tool for retrieving all known hosts.

### Testing / validation
- `python3 -m py_compile src/processes/mcp.py src/database/localhosts.py tests/test_mcp.py tests/test_localhosts.py` passed.
- `python3 -m unittest tests.test_mcp tests.test_localhosts` passed.
- `python3 -m unittest discover tests` was attempted but could not complete because this environment is missing the unrelated `requests` dependency required by existing notification/API tests.
- `python3 -m pytest tests/test_mcp.py` was attempted but could not run because `pytest` is not installed in this environment.

### Open questions
- None.
