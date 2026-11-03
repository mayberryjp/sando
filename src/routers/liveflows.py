import json
import logging

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
        Returns the most recent flows from newflows sorted by last_seen DESC.

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
            response.content_type = "application/json"
            return json.dumps({"success": True, "data": data, "count": len(data)})
        except Exception as e:
            log_error(logger, f"[ERROR] api_liveflows_snapshot: {e}")
            response.status = 500
            return json.dumps({"success": False, "error": str(e)})

    @app.get("/api/liveflows/since")
    @app.get("/api/liveflows/poll")
    def api_liveflows_since():
        """
        Returns newflows rows active in the last N seconds, oldest first.

        Query params:
            seconds (int): Lookback window in seconds (default 60, max 3600).
            limit   (int): Max rows per poll (default 500).
        """
        logger = logging.getLogger(__name__)
        try:
            seconds = min(int(request.query.get("seconds", 60)), 3600)
            limit = min(
                int(request.query.get("limit", _DEFAULT_DELTA_LIMIT)),
                _MAX_SNAPSHOT_LIMIT,
            )
            data = get_flows_since(seconds=seconds, limit=limit)
            response.content_type = "application/json"
            return json.dumps({"success": True, "data": data, "count": len(data)})
        except Exception as e:
            log_error(logger, f"[ERROR] api_liveflows_since: {e}")
            response.status = 500
            return json.dumps({"success": False, "error": str(e)})

    @app.get("/api/liveflows/stats")
    def api_liveflows_stats():
        """
        Returns aggregate stats for flows active in the last N seconds.

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
