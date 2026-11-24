import re
from html import escape

from src.database.localhosts import get_localhost_by_ip


def format_alert_message(
    message, flow, local_ip=None, local_description=None, escape_descriptions=False
):
    """Label flow endpoints with their local inventory descriptions."""
    message = message or ""
    descriptions = {}
    if local_ip:
        descriptions[local_ip] = local_description

    if isinstance(flow, (list, tuple)) and len(flow) >= 2:
        for ip in flow[:2]:
            if not isinstance(ip, str) or ip in descriptions:
                continue
            host = get_localhost_by_ip(ip)
            descriptions[ip] = host[12] if host and len(host) > 12 else None

    for ip, description in descriptions.items():
        description = (description or "").strip().upper()
        if not description:
            continue
        if escape_descriptions:
            description = escape(description)
        pattern = rf"\b{re.escape(ip)}\b"
        message = re.sub(
            pattern, lambda match: f"{match.group(0)} ({description})", message
        )
    return message
