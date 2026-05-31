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
- Before finishing, create or update .agent/change-summaries/issue-43-backend.md.
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

# GitHub Issue #43

URL: https://github.com/mayberryjp/sando/issues/43

Title: Add get networks mcp tool call

Labels: sando_backend_agent_delegated

Author: @mayberryjp

## Original Issue Body

Please use existing database function
List all the networks from configuration 
Include ipv4 and ipv6 networks



## Issue Comments / Conversation

### Comment by @mayberryjp at 2026-05-31T05:49:36Z

Codex implementation notes

Expected behavior:
- Add an MCP tool for listing configured local networks, likely named `list_networks` or `get_networks`; use the naming style already in `src/processes/mcp.py`.
- The source of truth is the `LocalNetworks` configuration value. `src/database/configuration.py` already has `get_local_network_cidrs(config_dict)`, but that helper returns only CIDR strings and drops metadata. If the tool needs IPv4/IPv6 distinction, parse the same `LocalNetworks` JSON and preserve/normalize `ip_version`.
- Include both IPv4 and IPv6 networks. Existing helpers default a missing `ip_version` to IPv4; keep that behavior for backward compatibility.

Likely files/areas:
- `src/processes/mcp.py`: import/use `get_all_configuration` and register the new MCP tool via `@mcp_tool`.
- `src/database/configuration.py`: consider adding a small helper that returns normalized local network objects if that keeps parsing out of the MCP layer.

Edge cases:
- `LocalNetworks` may be `[]`, missing, malformed JSON, or contain older entries without `ip_version`.
- Some scopes may include router/site-like metadata; do not drop it unless intentionally narrowing the response. At minimum return `cidr` and normalized `ip_version`.

Acceptance criteria:
- `tools/list` shows the new network-listing tool.
- `tools/call` returns a JSON-serializable list of configured networks with IPv4 and IPv6 entries represented distinctly.
- Empty config returns an empty list without crashing.

Test suggestions:
- Unit-test/quick script the parser with mixed IPv4/IPv6 `LocalNetworks`, missing `ip_version`, and malformed JSON.
- Exercise the MCP JSON-RPC `tools/call` path for the new tool.

Uncertainty:
- The issue says “use existing database function”; `get_local_network_cidrs` exists but does not preserve IPv4/IPv6 metadata beyond the CIDR text. If the product expectation is strict metadata output, add a helper beside it rather than changing existing callers unexpectedly.

