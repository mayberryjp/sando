import json
import logging
from datetime import datetime, timedelta

from bottle import Bottle, request, response

from src.database.liveflows import get_flows_since, get_live_snapshot, get_live_stats
from src.utils.locallogging import log_error

app = Bottle()

_DEFAULT_SNAPSHOT_LIMIT = 200
_MAX_SNAPSHOT_LIMIT = 2000
_DEFAULT_DELTA_LIMIT = 500
_DEFAULT_STATS_WINDOW = 60  # seconds


def setup_liveflows_routes(app):

    @app.get("/api/liveflows")
    def api_liveflows_snapshot():
        """
        Returns the most recent flows sorted by last_seen DESC.

        Query params:
            limit (int): Max rows to return (default 200, max 2000).
        """
        logger = logging.getLogger(__name__)
        try:
            limit = min(
                int(request.query.get("limit", _DEFAULT_SNAPSHOT_LIMIT)),
                _MAX_SNAPSHOT_LIMIT,
            )
            data = get_live_snapshot(limit=limit)
            # Provide the oldest last_seen so the client has a cursor to start polling from
            since = data[-1]["last_seen"] if data else _default_since(seconds=30)
            response.content_type = "application/json"
            return json.dumps(
                {"success": True, "data": data, "count": len(data), "since": since}
            )
        except Exception as e:
            log_error(logger, f"[ERROR] api_liveflows_snapshot: {e}")
            response.status = 500
            return json.dumps({"success": False, "error": str(e)})

    @app.get("/api/liveflows/since")
    def api_liveflows_since():
        """
        Returns flows where last_seen > since, ordered oldest-first.
        Used for polling-based real-time updates.

        Query params:
            since (str): ISO datetime string or SQLite-compatible timestamp (required).
                         Example: "2024-01-15 10:30:00"
            limit (int): Max rows per poll (default 500).
        """
        logger = logging.getLogger(__name__)
        try:
            since = request.query.get("since", "")
            if not since:
                response.status = 400
                return json.dumps(
                    {"success": False, "error": "Missing required parameter: since"}
                )

            # Clamp limit to avoid overloading the client
            limit = min(
                int(request.query.get("limit", _DEFAULT_DELTA_LIMIT)),
                _MAX_SNAPSHOT_LIMIT,
            )

            data = get_flows_since(since, limit=limit)

            # Return the next cursor: max last_seen in this batch, or echo back since if empty
            next_since = data[-1]["last_seen"] if data else since

            response.content_type = "application/json"
            return json.dumps(
                {
                    "success": True,
                    "data": data,
                    "count": len(data),
                    "since": since,
                    "next_since": next_since,
                }
            )
        except Exception as e:
            log_error(logger, f"[ERROR] api_liveflows_since: {e}")
            response.status = 500
            return json.dumps({"success": False, "error": str(e)})

    @app.get("/api/liveflows/stats")
    def api_liveflows_stats():
        """
        Returns aggregate stats for flows active in the last N seconds.
        Suitable for top-talkers dashboards, protocol breakdowns, etc.

        Query params:
            window (int): Lookback window in seconds (default 60, max 3600).
        """
        logger = logging.getLogger(__name__)
        try:
            window = min(int(request.query.get("window", _DEFAULT_STATS_WINDOW)), 3600)
            data = get_live_stats(window_seconds=window)
            response.content_type = "application/json"
            return json.dumps({"success": True, "data": data})
        except Exception as e:
            log_error(logger, f"[ERROR] api_liveflows_stats: {e}")
            response.status = 500
            return json.dumps({"success": False, "error": str(e)})


def _default_since(seconds=30):
    return (datetime.now() - timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
