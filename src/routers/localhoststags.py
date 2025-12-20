from bottle import Bottle, request, response

from src.database.localhoststags import add_tag_to_localhost, delete_tag_from_localhost

app = Bottle()


def setup_localhoststags_routes(app):

    @app.put("/api/localhosttags/<ip_address>")
    def api_add_tag(ip_address):
        """
        Add a tag to the specified localhost.
        Expects JSON body: {"tag": "tagname"}
        """
        try:
            data = request.json
            tag = data.get("tag") if data else None
            if not tag:
                response.status = 400
                return {"success": False, "error": "Missing 'tag' in request body"}
            add_tag_to_localhost(ip_address, tag)
            return {"success": True, "message": f"Tag '{tag}' added to {ip_address}"}
        except Exception as e:
            response.status = 500
            return {"success": False, "error": str(e)}

    @app.delete("/api/localhosttags/<ip_address>")
    def api_delete_tag(ip_address):
        """
        Remove a tag from the specified localhost.
        Expects JSON body: {"tag": "tagname"}
        """
        try:
            data = request.json
            tag = data.get("tag") if data else None
            if not tag:
                response.status = 400
                return {"success": False, "error": "Missing 'tag' in request body"}
            delete_tag_from_localhost(ip_address, tag)
            return {
                "success": True,
                "message": f"Tag '{tag}' removed from {ip_address}",
            }
        except Exception as e:
            response.status = 500
            return {"success": False, "error": str(e)}
