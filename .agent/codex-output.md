Implemented issue #43.

Added:
- `get_local_networks(config_dict)` in [src/database/configuration.py](/tmp/runner/work/sando/sando/src/database/configuration.py:67)
- `get_networks` MCP tool in [src/processes/mcp.py](/tmp/runner/work/sando/sando/src/processes/mcp.py:105)
- Focused tests in `tests/test_configuration_local_networks.py` and `tests/test_mcp_networks.py`
- Required summary at `.agent/change-summaries/issue-43-backend.md`

Behavior:
- Reads `LocalNetworks` from configuration via `get_all_configuration()`.
- Returns a JSON-serializable list of network objects.
- Preserves existing metadata like `router`/`site`.
- Normalizes missing/string `ip_version`, defaulting missing values to IPv4.
- Malformed, missing, or empty config returns `[]`.

Validation:
- `python3 -m py_compile ...` passed.
- Direct parser validation passed.
- Direct MCP registry/tool validation passed using a lightweight Bottle stub.
- `pytest` could not be run because it is not installed in this environment.

Note: `.agent/issue.md` was already modified before my changes; I left it untouched.