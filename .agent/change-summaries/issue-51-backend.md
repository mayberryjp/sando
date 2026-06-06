## Agent Change Summary

### Agent
- Backend

### GitHub issue
- #51

### What changed
- Added MCP tools `list_explore_flows` and `search_explore_flows` in `src/processes/mcp.py`.
- Added MCP tools `search_dns_keyvalue` and `search_dns_queries` in `src/processes/mcp.py`.
- Added database-layer helper `search_dns_keyvalue` in `src/database/explore.py`.
- Added database-layer helper `search_dns_queries` in `src/database/dnsqueries.py`.

### User-facing impact
- MCP clients can inspect paginated Explore flow rows, search Explore concat data, search DNS enrichment IP/domain rows, and search raw DNS query history without using REST endpoints or direct SQLite access.

### Files changed
- `src/processes/mcp.py`
- `src/database/explore.py`
- `src/database/dnsqueries.py`
- `.agent/change-summaries/issue-51-backend.md`

### README impact
- No README changes were made.

### Announcement impact
- New MCP tools are available for Explore and DNS investigation workflows.

### Testing / validation
- Ran `python3 -m py_compile src/processes/mcp.py src/database/explore.py src/database/dnsqueries.py`.
- Ran a Python registry check confirming `list_explore_flows`, `search_explore_flows`, `search_dns_keyvalue`, and `search_dns_queries` are registered in `src.processes.mcp.TOOLS`.
- Ran direct MCP tool function calls against temporary SQLite databases and verified the four new tool results are JSON-serializable.
- No automated test suite was present in the repository.

### Open questions
- None.
