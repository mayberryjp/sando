## Agent Change Summary

### Agent
- Backend

### GitHub issue
- #53

### What changed
- Added `get_aggregate_traffic_stats()` to aggregate traffic stats across all hosts for the last 100 hourly intervals.
- Added `GET /api/trafficstats` to return the aggregate site-wide traffic stats series.
- The aggregate response includes `timestamp`, `total_packets`, `total_bytes`, and `alerts` for each hour.

### User-facing impact
- API clients can request `/api/trafficstats` to render a continuous site-wide 100-hour traffic chart.
- Empty traffic hours are returned with zero-valued traffic and alert counts.

### Files changed
- `src/database/trafficstats.py`
- `src/routers/trafficstats.py`
- `.agent/change-summaries/issue-53-backend.md`

### README impact
- README may need an API endpoint entry for `GET /api/trafficstats` if API routes are documented there.

### Announcement impact
- New backend API endpoint for aggregate site-wide traffic stats.

### Testing / validation
- Passed: `python3 -m py_compile src/database/trafficstats.py src/routers/trafficstats.py`
- Passed: ad hoc SQLite validation for aggregation across multiple IPs, empty-hour zero filling, alert grouping, response keys, 100 returned rows, and most-recent-first ordering.
- Not run: route-level Bottle smoke test because the runner is missing the `bottle` dependency.

### Open questions
- None.
