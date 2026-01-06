# Bandwidth anomaly detection for localhosts
import logging
from src.database.trafficstats import get_all_ips_traffic_status, get_traffic_stats_for_ip
from src.database.localhosts import get_localhosts_all
from src.notifications.core import handle_alert
from src.utils.locallogging import log_info

def detect_bandwidth_anomaly(config_dict):
	"""
	For each known localhost, get the last 100 hours of traffic stats.
	Calculate the average total_bytes for the oldest 99 hours, then compare the current hour to this average.
	If the current hour exceeds the average, trigger an alert.
	"""
	logger = logging.getLogger(__name__)
	log_info(logger, "[INFO] Starting bandwidth anomaly detection for all localhosts.")

	# Get all localhosts with full details
	localhosts = get_localhosts_all()
	if not localhosts:
		log_info(logger, "[INFO] No localhosts found for bandwidth anomaly detection.")
		return

	# Get traffic status for all IPs (not strictly needed, but could be used to skip inactive hosts)
	ip_traffic_status = get_all_ips_traffic_status()

	for host in localhosts:
		ip = host.get("ip_address")
		if not ip:
			continue

		# Optionally skip hosts with no traffic in last 100 hours
		if not ip_traffic_status.get(ip, False):
			continue

		# Get last 100 hours of traffic stats for this IP
		stats = get_traffic_stats_for_ip(ip)
		if not stats or len(stats) < 2:
			continue  # Not enough data

		# Sort stats by timestamp ascending (oldest first)
		stats_sorted = sorted(stats, key=lambda x: x["timestamp"])
		# Only consider stats with valid total_bytes
		valid_stats = [s for s in stats_sorted if s["total_bytes"] is not None]
		if len(valid_stats) < 2:
			continue

		# Oldest 99 hours (excluding the most recent hour)
		if len(valid_stats) < 100:
			# Not enough data for a full 99-hour average, skip
			continue
		oldest_99 = valid_stats[:-1]
		current_hour = valid_stats[-1]


		avg_bytes = sum(s["total_bytes"] for s in oldest_99) / len(oldest_99)
		current_bytes = current_hour["total_bytes"]
		multiplier = float(config_dict.get("BandwidthAnomalyMuliplierThreshold", 10))
		threshold = avg_bytes * multiplier

		if current_bytes is not None and current_bytes > threshold:
			alert_id = f"{ip}_BandwidthAnomaly_{current_hour['timestamp']}"
			message = (
				f"Bandwidth Anomaly Detected:\n"
				f"IP Address: {ip}\n"
				f"Current Hour Bytes: {current_bytes}\n"
				f"Threshold ({multiplier}x Avg): {threshold:.2f}\n"
				f"Average Previous 99 Hours: {avg_bytes:.2f}\n"
				f"Timestamp: {current_hour['timestamp']}"
			)
			log_info(
				logger,
				f"[INFO] Bandwidth anomaly detected for {ip}: Current={current_bytes}, Threshold={threshold:.2f}, Avg99={avg_bytes:.2f}"
			)
			handle_alert(
				config_dict,
				"BandwidthAnomalyDetection",
				message,
				ip,
				current_hour,
				"Bandwidth Anomaly Detected",
				f"Current: {current_bytes}",
				f"Threshold: {threshold:.2f}",
				alert_id,
			)

	log_info(logger, "[INFO] Finished bandwidth anomaly detection for all localhosts.")
