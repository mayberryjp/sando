import json
import logging
import os
import time
import zipfile

import requests

from src.utils.locallogging import log_error, log_info, log_warn
from src.utils.network import ip_network_to_range

ASN_DOWNLOAD_URL = "https://geoip.oxl.app/file/asn_ipv4_full.json.zip"
ASN_DOWNLOAD_MAX_ATTEMPTS = 10


def _get_remote_etag(url):
    """Return the remote file's ETag, or None. HEAD is rejected (405), so use a 1-byte ranged GET."""
    try:
        with requests.get(
            url, headers={"Range": "bytes=0-0"}, stream=True, timeout=30
        ) as response:
            if response.status_code in (200, 206):
                return response.headers.get("ETag")
    except requests.exceptions.RequestException:
        pass
    return None


def _read_saved_etag(path):
    try:
        with open(path, "r") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _download_with_resume(url, dest_path, logger):
    """
    Stream a file to disk, resuming with HTTP Range requests after dropped
    connections (common on slow links). Returns the file's ETag ("" if the
    server sent none) once the file is complete, or None on failure.
    """
    if os.path.exists(dest_path):
        os.remove(dest_path)

    total_size = None
    etag = ""
    for attempt in range(1, ASN_DOWNLOAD_MAX_ATTEMPTS + 1):
        offset = os.path.getsize(dest_path) if os.path.exists(dest_path) else 0
        headers = {"Range": f"bytes={offset}-"} if offset else {}
        if offset and etag:
            # Server returns the full file (200) instead of a stale partial if it changed
            headers["If-Range"] = etag

        try:
            # (connect timeout, per-read timeout); slow links need a generous read timeout
            with requests.get(
                url, stream=True, timeout=(30, 60), headers=headers
            ) as response:
                if response.status_code == 416 and total_size and offset >= total_size:
                    return etag
                if response.status_code not in (200, 206):
                    log_error(
                        logger,
                        f"[ERROR] Failed to download ASN database: {response.status_code}",
                    )
                    return None

                etag = response.headers.get("ETag", etag)
                if response.status_code == 200:
                    # Server ignored Range (or this is a fresh start); restart from zero
                    offset = 0
                    mode = "wb"
                    total_size = int(response.headers.get("Content-Length", 0)) or None
                else:
                    mode = "ab"
                    content_range = response.headers.get("Content-Range", "")
                    if "/" in content_range and content_range.split("/")[-1].isdigit():
                        total_size = int(content_range.split("/")[-1])

                with open(dest_path, mode) as f:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if chunk:
                            f.write(chunk)

            final_size = os.path.getsize(dest_path)
            if total_size and final_size < total_size:
                raise requests.exceptions.ChunkedEncodingError(
                    f"Incomplete download: {final_size} of {total_size} bytes"
                )
            return etag

        except (requests.exceptions.RequestException, OSError) as e:
            log_warn(
                logger,
                f"[WARN] ASN download attempt {attempt}/{ASN_DOWNLOAD_MAX_ATTEMPTS} interrupted: {e}",
            )
            time.sleep(min(5 * attempt, 30))

    log_error(
        logger,
        f"[ERROR] Giving up on ASN database download after {ASN_DOWNLOAD_MAX_ATTEMPTS} attempts.",
    )
    return None


def create_asn_database():
    """
    Downloads ASN (Autonomous System Number) data from oxl.app,
    extracts IP ranges and ISP information, and stores it in a database.

    This enables IP to ISP lookups to identify the provider of an IP address.
    """
    logger = logging.getLogger(__name__)

    try:
        # Step 1: Create temporary directory if it doesn't exist
        temp_dir = "/database"
        os.makedirs(temp_dir, exist_ok=True)
        zip_path = os.path.join(temp_dir, "asn_ipv4_full.json.zip")
        json_path = os.path.join(temp_dir, "asn_ipv4_full.json")

        etag_path = os.path.join(temp_dir, "asn_ipv4_full.etag")

        # Step 2: Skip if the remote file is unchanged since the last successful import
        remote_etag = _get_remote_etag(ASN_DOWNLOAD_URL)
        if remote_etag and remote_etag == _read_saved_etag(etag_path):
            log_info(logger, "[INFO] ASN database unchanged on server, skipping download.")
            return

        # Step 3: Download the ASN data file (resumable, streamed to disk)
        log_info(logger, "[INFO] Downloading ASN database from oxl.app...")
        downloaded_etag = _download_with_resume(ASN_DOWNLOAD_URL, zip_path, logger)
        if downloaded_etag is None:
            return

        # Step 3: Extract the ZIP file
        log_info(logger, "[INFO] Extracting ASN database ZIP file...")
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        # Step 4: Ensure we have the extracted JSON file
        if not os.path.exists(json_path):
            log_error(logger, "[ERROR] ASN JSON file not found after extraction")
            return

        # Step 6: Parse the JSON and insert data into database
        log_info(logger, "[INFO] Processing ASN data and inserting into database...")

        try:
            # For large files, process the data
            count = 0
            with open(json_path, "r") as json_file:
                data = json.load(json_file)

                # New JSON structure is a dictionary with ASNs as keys
                if not isinstance(data, dict):
                    log_error(
                        logger,
                        f"[ERROR] Expected a dictionary of ASN entries, got {type(data).__name__}",
                    )
                    return

                total_entries = sum(
                    len(asn_data.get("ipv4", [])) for asn_data in data.values()
                )
                log_info(
                    logger,
                    f"[INFO] Found ASN data for {len(data)} ASNs with approximately {total_entries} network entries",
                )

                # Process in batches for better performance
                batch_size = 1000
                current_batch = []

                # Loop through each ASN entry
                for asn, asn_data in data.items():
                    # Skip if not a dictionary
                    if not isinstance(asn_data, dict):
                        log_warn(logger, f"[WARN] Skipping invalid ASN data for {asn}")
                        continue

                    # Get IPv4 networks
                    ipv4_networks = asn_data.get("ipv4", [])
                    if not ipv4_networks:
                        continue

                    # Get organization info
                    org_info = asn_data.get("organization", {})
                    org_name = (
                        org_info.get("name", "") if isinstance(org_info, dict) else ""
                    )

                    # Process each network for this ASN
                    for network in ipv4_networks:
                        # Convert network CIDR to start_ip, end_ip, netmask
                        start_ip, end_ip, netmask = ip_network_to_range(network)
                        if start_ip is None:
                            continue

                        # Add to current batch
                        current_batch.append(
                            (network, start_ip, end_ip, netmask, str(asn), org_name)
                        )

                        # Execute batch when it reaches the desired size
                        if len(current_batch) >= batch_size:
                            from src.database.ipasn import insert_asn_records_batch

                            success, inserted = insert_asn_records_batch(current_batch)
                            if success:
                                count += inserted
                            current_batch = []

                # Insert any remaining entries in the last batch
                if current_batch:
                    from src.database.ipasn import insert_asn_records_batch

                    success, inserted = insert_asn_records_batch(current_batch)
                    if success:
                        count += inserted

        except json.JSONDecodeError as e:
            log_error(logger, f"[ERROR] Invalid JSON format in ASN data file: {e}")
            return

        log_info(
            logger, f"[INFO] ASN database created successfully with {count} entries"
        )

        if downloaded_etag:
            with open(etag_path, "w") as f:
                f.write(downloaded_etag)

        # Step 8: Clean up temporary files
        if os.path.exists(zip_path):
            os.remove(zip_path)
        if os.path.exists(json_path):
            os.remove(json_path)

    except Exception as e:
        log_error(logger, f"[ERROR] Error creating ASN database: {e}")
