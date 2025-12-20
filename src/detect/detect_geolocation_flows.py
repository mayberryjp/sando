import logging

from src.notifications.core import handle_alert
from src.utils.locallogging import log_info, log_warn
from src.utils.network import ip_to_int


def detect_geolocation_flows(rows, config_dict, geolocation_data):
    """
    Optimized version of geolocation flow detection.
    Uses set lookups and precomputed data structures for better performance.
    """
    logger = logging.getLogger(__name__)

    log_info(logger, "[INFO] Started detecting flows involving banned geolocations")

    # Convert banned countries to a set for O(1) lookups
    banned_countries = set(
        country.strip()
        for country in config_dict.get("BannedCountryList", "").split(",")
        if country.strip()
    )

    if not banned_countries:
        log_warn(logger, "[WARN] No banned countries specified in BannedCountryList.")
        return

    # Debug: Print banned countries
    # log_info(logger, f"[DEBUG] Banned countries: {banned_countries}")

    # Pre-process geolocation data into ranges
    geo_ranges = []
    for entry in geolocation_data:
        if len(entry) >= 5:  # Ensure entry has at least 5 elements
            network, start_ip, end_ip, netmask, country = entry[
                :5
            ]  # Take first 4 elements
            if country in banned_countries:
                geo_ranges.append((start_ip, end_ip, netmask, country))

    # Sort ranges by start_ip for efficient lookup
    geo_ranges.sort(key=lambda x: x[0])

    def find_matching_country(ip_int):
        """Find matching country for an IP using linear search with early exit"""
        if not ip_int:
            return None

        best_match = None
        best_netmask = -1

        for start_ip, end_ip, netmask, country in geo_ranges:
            if start_ip <= ip_int <= end_ip:
                if netmask > best_netmask:
                    best_match = country
                    best_netmask = netmask
            elif start_ip > ip_int:
                break  # Early exit if we've passed possible matches

        return best_match

    # Process rows
    total = len(rows)
    matches = 0
    for index, row in enumerate(rows, 1):
        if index % 1000 == 0:
            print(
                f"\rProcessing geolocation flows: {index}/{total} (matches: {matches})",
                end="",
                flush=True,
            )

        src_ip, dst_ip, src_port, dst_port, protocol, *_ = row

        # Convert IPs to integers
        src_ip_int = ip_to_int(src_ip)
        dst_ip_int = ip_to_int(dst_ip)

        if not src_ip_int and not dst_ip_int:
            continue

        # Find matching countries
        src_country = find_matching_country(src_ip_int)
        dst_country = find_matching_country(dst_ip_int)

        # log_info(logger, f"[DEBUG] src_ip: {src_ip}, dst_ip: {dst_ip}, src_country: {src_country}, dst_country: {dst_country}")
        if src_country or dst_country:
            log_info(
                logger,
                f"[INFO] Flow involves an IP in a banned country: {src_ip} ({src_country}) and {dst_ip} ({dst_country})",
            )

            local_ip = None
            remote_ip = None
            remote_country = None
            if dst_country is not None:
                local_ip = src_ip
                remote_country = dst_country
                remote_ip = dst_ip
            elif src_country is not None:
                local_ip = dst_ip
                remote_country = src_country
                remote_ip = src_ip

            matches += 1
            message = (
                f"Flow involves an IP in a banned country:\n"
                f"Local IP: {local_ip}\n"
                f"Remote IP: {remote_ip} ({remote_country or 'N/A'})"
            )

            alert_id = f"{local_ip}_{remote_ip}_{protocol}_BannedCountryDetection"

            handle_alert(
                config_dict,
                "GeolocationFlowsDetection",
                message,
                local_ip,
                row,
                "Flow involves an IP in a banned country",
                remote_ip,
                remote_country,
                alert_id,
            )

    print()  # Final newline
    log_info(
        logger,
        f"[INFO] Completed geolocation processing. Found {matches} matches in {total} flows",
    )
