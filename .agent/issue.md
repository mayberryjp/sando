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
- Before finishing, create or update .agent/change-summaries/issue-33-backend.md.
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

# GitHub Issue #33

URL: https://github.com/mayberryjp/sando/issues/33

Title: Bump up base image version

Labels: sando_backend_agent_delegated

Author: @mayberryjp

## Original Issue Body



## Issue Comments / Conversation

### Comment by @mayberryjp at 2026-05-28T10:53:44Z

In the Dockerfile

