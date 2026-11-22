import ipaddress
import logging
import os
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from src.const import (
    CONST_IPFIX_LISTEN_ADDRESS,
    CONST_IPFIX_LISTEN_PORT,
    CONST_IPFIX_MAX_TEMPLATES,
    CONST_IPFIX_TEMPLATE_LIFETIME,
)
from src.utils.flow_collector import run_flow_collector
from src.utils.locallogging import log_warn


@dataclass(frozen=True)
class Template:
    fields: Tuple[Tuple[int, int, Optional[int]], ...]
    options: bool
    refreshed: float

    @property
    def minimum_size(self):
        return sum(1 if length == 65535 else length for _, length, _ in self.fields)


# Standard flow IEs; integer fields permit IPFIX reduced-size encoding.
FLOW_FIELDS = {
    1: ("bytes", 8), 2: ("packets", 8), 4: ("protocol", 1),
    5: ("tos", 1), 6: ("tcp_flags", 2), 7: ("src_port", 2),
    9: ("src_mask", 1), 10: ("input_iface", 4), 11: ("dst_port", 2),
    13: ("dst_mask", 1), 14: ("output_iface", 4),
    16: ("src_as", 4), 17: ("dst_as", 4),
    29: ("src_mask", 1), 30: ("dst_mask", 1),
    60: ("ip_version", 1),
    34: ("sampling_interval", 4), 35: ("sampling_algorithm", 1),
    152: ("flow_start_ms", 8), 153: ("flow_end_ms", 8),
}
ADDRESS_FIELDS = {
    8: ("src_ipv4", 4), 12: ("dst_ipv4", 4), 15: ("nexthop_ipv4", 4),
    27: ("src_ipv6", 16), 28: ("dst_ipv6", 16), 62: ("nexthop_ipv6", 16),
}


class IPFIXDecoder:
    """UDP templates are scoped by exporter endpoint and observation domain."""

    def __init__(self, template_lifetime=CONST_IPFIX_TEMPLATE_LIFETIME,
                 max_templates=CONST_IPFIX_MAX_TEMPLATES):
        if template_lifetime <= 0 or max_templates <= 0:
            raise ValueError("IPFIX template lifetime and capacity must be positive")
        self.template_lifetime = template_lifetime
        self.max_templates = max_templates
        self.templates = OrderedDict()
        self.logger = logging.getLogger(__name__)

    def parse_packet(self, data, addr, received_at=None):
        received_at = time.time() if received_at is None else received_at
        if len(data) < 16:
            raise ValueError("Truncated IPFIX header")
        version, length, export_time, sequence, domain = struct.unpack("!HHIII", data[:16])
        if version != 10:
            raise ValueError(f"Expected IPFIX v10, got version {version}")
        if length != len(data):
            raise ValueError(f"IPFIX message length {length} does not match datagram {len(data)}")
        now = time.monotonic()
        for key, template in list(self.templates.items()):
            if now - template.refreshed >= self.template_lifetime:
                del self.templates[key]
        session = (tuple(addr), domain)
        records = []
        offset = 16
        while offset < length:
            if offset + 4 > length:
                raise ValueError("Truncated IPFIX set header")
            set_id, set_length = struct.unpack_from("!HH", data, offset)
            if set_length < 4 or offset + set_length > length:
                raise ValueError("Invalid IPFIX set length")
            payload = data[offset + 4:offset + set_length]
            if set_id in (2, 3):
                self._read_templates(payload, session, set_id == 3, now)
            elif set_id >= 256:
                key = (*session, set_id)
                template = self.templates.get(key)
                if template is None:
                    log_warn(self.logger, f"[WARN] IPFIX data from {addr}, domain {domain}: missing or expired template {set_id}; dropping set")
                else:
                    self.templates.move_to_end(key)
                    records.extend(self._read_records(payload, template, received_at))
            else:
                log_warn(self.logger, f"[WARN] Unsupported IPFIX set ID {set_id}; dropping set")
            offset += set_length
        return records

    def _read_templates(self, payload, session, options, now):
        offset = 0
        while offset < len(payload):
            remaining = payload[offset:]
            if len(remaining) <= 3 and not any(remaining):
                break
            header_size = 6 if options else 4
            if offset + header_size > len(payload):
                raise ValueError("Truncated IPFIX template header")
            template_id, count = struct.unpack_from("!HH", payload, offset)
            scope_count = struct.unpack_from("!H", payload, offset + 4)[0] if options else 0
            offset += header_size
            if count == 0:
                if scope_count != 0:
                    raise ValueError("Invalid IPFIX options template withdrawal")
                if template_id != (3 if options else 2) and template_id < 256:
                    raise ValueError("Invalid IPFIX template withdrawal ID")
                # RFC 7011 forbids withdrawals over UDP; rely on expiry/refresh.
                log_warn(self.logger, f"[WARN] Ignoring IPFIX template withdrawal {template_id} over UDP")
                continue
            if template_id < 256 or (options and not 0 < scope_count <= count):
                raise ValueError("Invalid IPFIX template ID or scope count")
            fields = []
            for _ in range(count):
                if offset + 4 > len(payload):
                    raise ValueError("Truncated IPFIX field specifier")
                element, field_length = struct.unpack_from("!HH", payload, offset)
                offset += 4
                enterprise = None
                if element & 0x8000:
                    if offset + 4 > len(payload):
                        raise ValueError("Truncated IPFIX enterprise number")
                    enterprise = struct.unpack_from("!I", payload, offset)[0]
                    offset += 4
                if field_length == 0:
                    raise ValueError("Zero-length IPFIX template field")
                fields.append((element & 0x7FFF, field_length, enterprise))
            template = Template(tuple(fields), options, now)
            key = (*session, template_id)
            self.templates[key] = template
            self.templates.move_to_end(key)
            if len(self.templates) > self.max_templates:
                evicted, _ = self.templates.popitem(last=False)
                log_warn(self.logger, f"[WARN] IPFIX template cache full; evicted {evicted}")
            if not options and not self._is_flow_template(template):
                log_warn(self.logger, f"[WARN] IPFIX template {template_id} from {session} lacks addresses, protocol or delta counters; non-flow/total-counter records will not be ingested")

    @staticmethod
    def _is_flow_template(template):
        elements = {element for element, _, enterprise in template.fields if enterprise is None}
        return (
            {1, 2, 4}.issubset(elements)
            and ({8, 12}.issubset(elements) or {27, 28}.issubset(elements))
        )

    def _read_records(self, payload, template, received_at):
        offset = 0
        records = []
        flow_template = not template.options and self._is_flow_template(template)
        while offset < len(payload):
            remaining = payload[offset:]
            if len(remaining) < template.minimum_size:
                if len(remaining) <= 3 and not any(remaining):
                    break
                raise ValueError("Truncated IPFIX data record")
            values = {}
            for element, field_length, enterprise in template.fields:
                if field_length == 65535:
                    if offset >= len(payload):
                        raise ValueError("Truncated IPFIX variable-length field")
                    field_length = payload[offset]
                    offset += 1
                    if field_length == 255:
                        if offset + 2 > len(payload):
                            raise ValueError("Truncated IPFIX extended field length")
                        field_length = struct.unpack_from("!H", payload, offset)[0]
                        offset += 2
                if offset + field_length > len(payload):
                    raise ValueError("IPFIX field exceeds data set")
                value = payload[offset:offset + field_length]
                offset += field_length
                if not flow_template or enterprise is not None:
                    continue
                if element in ADDRESS_FIELDS:
                    name, expected = ADDRESS_FIELDS[element]
                    if field_length != expected:
                        raise ValueError(f"Invalid address size for IPFIX IE {element}")
                    values[name] = str(ipaddress.ip_address(value))
                elif element in FLOW_FIELDS:
                    name, maximum = FLOW_FIELDS[element]
                    if not 0 < field_length <= maximum:
                        raise ValueError(f"Invalid integer size for IPFIX IE {element}")
                    values[name] = int.from_bytes(value, "big")
            if flow_template:
                records.append(self._normalize(values, received_at))
        return records

    def _normalize(self, values, received_at):
        has_ipv6 = "src_ipv6" in values and "dst_ipv6" in values
        has_ipv4 = "src_ipv4" in values and "dst_ipv4" in values
        version = values.get("ip_version")
        if version is not None and version not in (4, 6):
            raise ValueError(f"Invalid IPFIX ipVersion: {version}")
        ipv6 = version == 6 or (version is None and has_ipv6 and not has_ipv4)
        if version is None and has_ipv4 and has_ipv6:
            ipv6_nonzero = values["src_ipv6"] != "::" or values["dst_ipv6"] != "::"
            ipv4_nonzero = values["src_ipv4"] != "0.0.0.0" or values["dst_ipv4"] != "0.0.0.0"
            if ipv6_nonzero and ipv4_nonzero:
                raise ValueError("IPFIX dual-family record requires ipVersion")
            ipv6 = ipv6_nonzero
        if (ipv6 and not has_ipv6) or (not ipv6 and not has_ipv4):
            raise ValueError("IPFIX ipVersion disagrees with address fields")
        family = "ipv6" if ipv6 else "ipv4"
        now = int(received_at)
        record = {
            "src_ip": values[f"src_{family}"],
            "dst_ip": values[f"dst_{family}"],
            "nexthop": values.get(f"nexthop_{family}", "::" if ipv6 else "0.0.0.0"),
            "start_time": now, "end_time": now, "last_seen": now,
            "tags": "", "times_seen": 1,
        }
        for name in {name for name, _ in FLOW_FIELDS.values()}:
            if name not in (
                "ip_version", "sampling_interval", "sampling_algorithm",
                "flow_start_ms", "flow_end_ms",
            ):
                record[name] = values.get(name, 0)
        interval = values.get("sampling_interval", 1)
        if interval < 1:
            raise ValueError("IPFIX samplingInterval must be positive")
        if interval != 1:
            log_warn(
                self.logger,
                f"[WARN] Sampled IPFIX export (interval {interval}); retaining observed counts without scaling. Configure unsampled exports for the shared flow pipeline.",
            )
        if values.get("sampling_algorithm", 1) != 1:
            log_warn(self.logger, "[WARN] Unsupported IPFIX sampling algorithm; retaining observed counts without scaling")

        for field, time_field in (("flow_start", "start_time"), ("flow_end", "end_time")):
            milliseconds = values.get(f"{field}_ms")
            if milliseconds is not None:
                seconds, fraction = divmod(milliseconds, 1000)
                try:
                    local_time = datetime.fromtimestamp(seconds)
                except (OverflowError, OSError, ValueError) as exc:
                    raise ValueError(f"IPFIX {field} timestamp is outside the supported datetime range") from exc
                record[field] = local_time.strftime("%Y-%m-%d %H:%M:%S") + f".{fraction:03d}"
                record[time_field] = seconds
        if (
            "flow_start_ms" in values and "flow_end_ms" in values
            and values["flow_start_ms"] > values["flow_end_ms"]
        ):
            log_warn(self.logger, "[WARN] IPFIX flow start is after flow end; preserving exported timestamps without correction")
        if record["packets"] > 0x7FFFFFFFFFFFFFFF or record["bytes"] > 0x7FFFFFFFFFFFFFFF:
            raise ValueError("IPFIX counter exceeds SQLite signed 64-bit storage")
        return record


def handle_ipfix():
    decoder = IPFIXDecoder()
    run_flow_collector(
        os.getenv("IPFIX_LISTEN_ADDRESS", CONST_IPFIX_LISTEN_ADDRESS),
        os.getenv("IPFIX_LISTEN_PORT", CONST_IPFIX_LISTEN_PORT),
        decoder.parse_packet, "IPFIX v10", "ipfix",
    )
