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
- Before finishing, create or update .agent/change-summaries/issue-42-backend.md.
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

# GitHub Issue #42

URL: https://github.com/mayberryjp/sando/issues/42

Title: add a list_hosts function to the mcp server

Labels: sando_backend_agent_delegated

Author: @mayberryjp

## Original Issue Body

There isnt an mcp tool to list all hosts on the network. please create a new tool method. it should list the hosts all the information known about those hosts. please use existing database functions to make this tool

## Issue Comments / Conversation

### Comment by @mayberryjp at 2026-05-31T05:49:37Z

Codex implementation notes

Expected behavior:
- Add an MCP tool to list all known hosts, likely named `list_hosts` to match the issue.
- It should return all information known about each host, using existing database access rather than duplicating SQL.

Likely files/areas:
- `src/processes/mcp.py`: import `get_localhosts_all` from `src.database.localhosts`, add a `@mcp_tool("list_hosts", ...)`, and include it in the module docstring’s Available tools list for consistency.
- `src/database/localhosts.py`: `get_localhosts_all()` already returns a list of dictionaries with the full localhost columns; use this directly unless a missing column is discovered during implementation.

Edge cases:
- No hosts should return `[]`, not an MCP error.
- Some host records may be MAC-only or have null IP/metadata; preserve fields as returned by the database.
- Keep response JSON-serializable; current `get_localhosts_all()` returns plain dicts/lists.

Acceptance criteria:
- `tools/list` includes `list_hosts`.
- Calling `list_hosts` returns every row from `localhosts` with the same full field set exposed by `get_localhosts_all()`.
- The existing `get_host`, `get_host_alerts`, and `export_whitelisted_hosts` tools still work.

Test suggestions:
- Add or run a focused MCP JSON-RPC smoke test for `tools/list` and `tools/call` with `list_hosts`.
- If there are existing route/API tests for `/api/localhosts`, mirror expected field coverage from that endpoint.

Uncertainty:
- The issue asks for “all the information known”; this likely means localhost table fields only. If flow summaries/alerts are desired too, that would become much heavier and overlap with `get_host`.

