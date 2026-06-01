# Copilot Instructions for Sando

## Architecture

Sando is a Python network monitoring backend that runs as multiple long-lived processes managed by supervisord (`src/super.conf`). Each process is a module in `src/processes/` invoked via `python -m src.processes.<name>`.

**Processes:** collector (NetFlow v5 UDP/2055), processor (scheduled detection runs), api (Bottle REST on TCP/8044), discovery, watchdog, fetch (integrations), sinkholedns, dhcpserver, mcp.

**Data layer:** Each logical domain has its own SQLite database file (paths in `src/const.py`). The `TABLE_DB_MAP` dict in `src/const.py` maps table names to database paths. All DB access goes through `src/database/core.py` (`connect_to_db(table_name)` → returns a `sqlite3.Connection`). There is also a `detached.py` variant for code that runs outside the normal module context.

**Key source layout:**
- `src/detect/` — Detection modules. Each file implements one detection (e.g., `detect_new_outbound_connections.py`). They receive flow rows + `config_dict` and call `handle_alert()`.
- `src/database/` — DB access functions per domain (alerts, localhosts, configuration, etc.).
- `src/routers/` — Bottle route handlers. Each file exports a `setup_*_routes(app)` function registered in `src/processes/api.py`.
- `src/notifications/` — Telegram and Discord alert dispatching via `core.handle_alert()`.
- `src/integrations/` — External data fetchers (Pi-hole, AdGuard, MaxMind, reputation lists, Tor, ASN).
- `src/utils/` — Shared helpers: logging (`locallogging`), network math (`network`), netflow parsing (`netflow`).

**Configuration:** All runtime settings live in the `configuration` SQLite table (key/value). Detections and services are toggled on/off via integer flags. `config_dict` is the standard dict passed around at runtime.

## Running Tests

Tests use `unittest` (no pytest config). Run from the repo root:

```bash
# Full suite
python -m pytest tests/

# Single test file
python -m pytest tests/test_notifications_core.py

# Single test method
python -m pytest tests/test_notifications_core.py::CoreNotificationTests::test_handle_alert_sends_discord_for_new_alerts
```

There is no configured linter or type checker in pyproject.toml. The `.ruff_cache` directory indicates ruff has been used manually:

```bash
ruff check src/
ruff format src/
```

## Conventions

- **API framework:** Bottle (not Flask/FastAPI). Routes are defined inside `setup_*_routes(app)` closures.
- **Logging:** Always use `src.utils.locallogging` helpers (`log_info`, `log_error`, `log_warn`) rather than raw `logging` calls.
- **Detection pattern:** Each detection is a standalone function that takes `(rows, config_dict)`, iterates flow rows, and calls `handle_alert()` for matches. Alert IDs follow the format `{src_ip}_{dst_ip}_{protocol}_{port}_{DetectionName}`.
- **Database access:** Use `connect_to_db(table_name)` which resolves the DB file via `TABLE_DB_MAP`. Always call `disconnect_from_db(conn)` after use.
- **Config access:** Configuration values are strings. Numeric settings are stored as `"0"`/`"1"` and compared as integers at runtime.
- **Module execution:** Processes are run as `python -m src.processes.<name>` from the repo root (or `/sando` in the container).
- **No ORM:** Raw SQL with `sqlite3` throughout. No SQLAlchemy or similar.
- **Constants:** All port numbers, DB paths, and global constants live in `src/const.py`.
