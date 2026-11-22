import ipaddress
import struct
import unittest
from unittest.mock import patch

from src.utils.ipfix import IPFIXDecoder
from src.utils.netflow import parse_netflow_v5_packet


IPV4_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 8), (1, 8)]
IPV6_FIELDS = [(27, 16), (28, 16), (7, 2), (11, 2), (4, 1), (2, 8), (1, 8)]
NETCONTROL_IPV4_FIELDS = [
    (8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (5, 1), (6, 1),
    (2, 8), (1, 8), (152, 8), (153, 8), (34, 4), (35, 1),
]
NETCONTROL_IPV6_FIELDS = [(27, 16), (28, 16)] + NETCONTROL_IPV4_FIELDS[2:]


def make_set(set_id, payload):
    return struct.pack("!HH", set_id, len(payload) + 4) + payload


def make_message(*sets, domain=1):
    payload = b"".join(sets)
    return struct.pack("!HHIII", 10, len(payload) + 16, 1700000000, 0, domain) + payload


def make_template(fields, template_id=256, options=False, scope_count=1):
    payload = struct.pack("!HH", template_id, len(fields))
    if options:
        payload += struct.pack("!H", scope_count)
    for field in fields:
        element, length = field[:2]
        payload += struct.pack("!HH", element | (0x8000 if len(field) == 3 else 0), length)
        if len(field) == 3:
            payload += struct.pack("!I", field[2])
    return make_set(3 if options else 2, payload)


def make_record(src="192.168.1.10", dst="8.8.8.8", packets=3, bytes_=300):
    return (
        ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
        + struct.pack("!HHBQQ", 50000, 443, 6, packets, bytes_)
    )


def make_netflow_packet(src="192.168.1.10", dst="8.8.8.8", packets=2, bytes_=200):
    header = struct.pack("!HHIIIIBBH", 5, 1, 1000, 1700000000, 0, 0, 0, 0, 0)
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        int(ipaddress.ip_address(src)), int(ipaddress.ip_address(dst)), 0,
        1, 2, packets, bytes_, 0, 1000, 50000, 443,
        0, 0, 6, 0, 0, 0, 24, 24, 0,
    )
    return header + record


def make_netcontrol_record(
    src="192.168.1.10", dst="8.8.8.8", packets=3, bytes_=300,
    start_ms=1700000000123, end_ms=1700000005456,
    sampling_interval=1, sampling_algorithm=1, tos=40, tcp_flags=18,
):
    return (
        ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
        + struct.pack(
            "!HHBBBQQQQIB", 50000, 443, 6, tos, tcp_flags, packets, bytes_,
            start_ms, end_ms, sampling_interval, sampling_algorithm,
        )
    )


def make_netcontrol_message(ipv4=(), ipv6=(), domain=1):
    templates = make_set(
        2,
        make_template(NETCONTROL_IPV4_FIELDS, template_id=256)[4:]
        + make_template(NETCONTROL_IPV6_FIELDS, template_id=257)[4:],
    )
    sets = [templates]
    if ipv4:
        sets.append(make_set(256, b"".join(ipv4)))
    if ipv6:
        sets.append(make_set(257, b"".join(ipv6)))
    return make_message(*sets, domain=domain)


class IPFIXDecoderTests(unittest.TestCase):
    ADDR = ("192.0.2.1", 12345)

    def setUp(self):
        self.decoder = IPFIXDecoder()
        patcher = patch("src.utils.ipfix.log_warn")
        self.warn = patcher.start()
        self.addCleanup(patcher.stop)

    def decode(self, *sets, domain=1, addr=None):
        return self.decoder.parse_packet(make_message(*sets, domain=domain), addr or self.ADDR)

    def test_ipv4_matches_netflow_normalized_shape(self):
        with patch("src.utils.ipfix.time.time", return_value=1700000100):
            record = self.decode(make_template(IPV4_FIELDS), make_set(256, make_record()))[0]
        legacy = parse_netflow_v5_packet(make_netflow_packet(), self.ADDR)[0]
        self.assertEqual(set(record), set(legacy))
        self.assertEqual(
            (record["src_ip"], record["dst_ip"], record["src_port"],
             record["dst_port"], record["protocol"], record["packets"], record["bytes"]),
            ("192.168.1.10", "8.8.8.8", 50000, 443, 6, 3, 300),
        )
        self.assertEqual(record["last_seen"], 1700000100)
        self.assertEqual(record["tags"], "")

    def test_ipv6_and_multiple_records(self):
        payload = make_record("2001:db8::1", "2001:4860:4860::8888")
        records = self.decode(make_template(IPV6_FIELDS), make_set(256, payload * 2))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["src_ip"], "2001:db8::1")
        self.assertEqual(records[0]["nexthop"], "::")

    def test_cached_template_in_subsequent_datagram(self):
        self.assertEqual(self.decode(make_template(IPV4_FIELDS)), [])
        self.assertEqual(len(self.decode(make_set(256, make_record()))), 1)

    def test_templates_are_scoped_to_exporter_endpoint_and_domain(self):
        self.decode(make_template(IPV4_FIELDS))
        for addr, domain in (
            (("192.0.2.2", 12345), 1), (("192.0.2.1", 12346), 1), (self.ADDR, 2),
        ):
            with self.subTest(addr=addr, domain=domain):
                self.assertEqual(self.decode(make_set(256, make_record()), addr=addr, domain=domain), [])
        self.decode(make_template(IPV6_FIELDS), domain=2)
        self.assertEqual(len(self.decode(make_set(256, make_record()))), 1)
        self.assertEqual(len(self.decode(make_set(256, make_record("2001:db8::1", "::1")), domain=2)), 1)
        self.assertEqual(self.warn.call_count, 3)

    def test_missing_template_logs_and_does_not_block_known_sets(self):
        records = self.decode(
            make_template(IPV4_FIELDS), make_set(999, b"unknown"),
            make_set(256, make_record()),
        )
        self.assertEqual(len(records), 1)
        self.warn.assert_called_once()

    def test_reduced_integer_encoding(self):
        fields = [(8, 4), (12, 4), (4, 1), (2, 2), (1, 4)]
        payload = ipaddress.ip_address("192.0.2.10").packed * 2 + struct.pack("!BHI", 1, 2, 400)
        record = self.decode(make_template(fields), make_set(256, payload))[0]
        self.assertEqual((record["src_port"], record["dst_port"], record["packets"], record["bytes"]), (0, 0, 2, 400))

    def test_enterprise_fields_do_not_override_standard_fields(self):
        fields = IPV4_FIELDS + [(1, 8, 1234)]
        payload = make_record() + struct.pack("!Q", 999999)
        record = self.decode(make_template(fields), make_set(256, payload))[0]
        self.assertEqual(record["bytes"], 300)

    def test_variable_length_fields_short_and_extended(self):
        fields = IPV4_FIELDS + [(82, 65535)]
        for value in (b"", b"abc", b"a" * 300):
            with self.subTest(length=len(value)):
                length = bytes([len(value)]) if len(value) < 255 else b"\xff" + struct.pack("!H", len(value))
                records = self.decode(
                    make_template(fields),
                    make_set(256, make_record() + length + value + make_record() + b"\0"),
                )
                self.assertEqual(len(records), 2)

    def test_options_template_data_does_not_become_a_flow(self):
        records = self.decode(
            make_template(IPV4_FIELDS, template_id=300, options=True),
            make_set(300, make_record()),
            make_template(IPV4_FIELDS), make_set(256, make_record()),
        )
        self.assertEqual(len(records), 1)

    def test_zero_padding_is_not_a_record(self):
        records = self.decode(
            make_template(IPV4_FIELDS),
            make_set(256, make_record() + b"\0" * 3),
        )
        self.assertEqual(len(records), 1)

    def test_template_refresh_replaces_layout(self):
        self.decode(make_template(IPV4_FIELDS))
        records = self.decode(
            make_template(IPV6_FIELDS),
            make_set(256, make_record("2001:db8::1", "::1")),
        )
        self.assertEqual(records[0]["dst_ip"], "::1")

    def test_udp_template_withdrawals_are_ignored(self):
        self.decode(make_template(IPV4_FIELDS))
        self.decode(make_set(2, struct.pack("!HH", 256, 0)))
        self.assertEqual(len(self.decode(make_set(256, make_record()))), 1)
        self.warn.assert_called_once()

    def test_templates_expire_without_refresh(self):
        with patch("src.utils.ipfix.time.monotonic", return_value=0):
            self.decode(make_template(IPV4_FIELDS))
        with patch("src.utils.ipfix.time.monotonic", return_value=1800):
            self.assertEqual(self.decode(make_set(256, make_record())), [])
        self.warn.assert_called_once()

    def test_template_refresh_extends_lifetime(self):
        with patch("src.utils.ipfix.time.monotonic", return_value=0):
            self.decode(make_template(IPV4_FIELDS))
        with patch("src.utils.ipfix.time.monotonic", return_value=1700):
            self.decode(make_template(IPV4_FIELDS))
        with patch("src.utils.ipfix.time.monotonic", return_value=1800):
            self.assertEqual(len(self.decode(make_set(256, make_record()))), 1)

    def test_cache_capacity_is_bounded(self):
        self.decoder = IPFIXDecoder(max_templates=1)
        self.decode(make_template(IPV4_FIELDS))
        self.decode(make_template(IPV4_FIELDS, template_id=257))
        self.assertEqual(len(self.decoder.templates), 1)
        self.assertEqual(self.decode(make_set(256, make_record())), [])
        self.assertEqual(len(self.decode(make_set(257, make_record()))), 1)

    def test_nonflow_and_total_counter_templates_are_not_ingested(self):
        for fields in ([(8, 4), (12, 4)], [(8, 4), (12, 4), (4, 1), (86, 8), (85, 8)]):
            with self.subTest(fields=fields):
                self.decode(make_template(fields))
                self.assertEqual(self.decode(make_set(256, b"\0" * sum(length for _, length in fields))), [])
        self.assertEqual(self.warn.call_count, 2)

    def test_both_address_families_honor_ip_version(self):
        fields = [(8, 4), (12, 4)] + IPV6_FIELDS + [(60, 1)]
        payload = b"\0" * 8 + make_record("2001:db8::1", "::1") + b"\x06"
        record = self.decode(make_template(fields), make_set(256, payload))[0]
        self.assertEqual(record["src_ip"], "2001:db8::1")
        payload = b"\0" * 8 + make_record("2001:db8::1", "::1") + b"\x05"
        with self.assertRaises(ValueError):
            self.decode(make_set(256, payload))

    def test_malformed_messages_and_sets_raise(self):
        valid = make_message(make_template(IPV4_FIELDS))
        invalid = [
            b"", valid[:15], b"\0\x09" + valid[2:],
            valid[:-1], valid + b"\0",
            make_message(b"\0"), make_message(struct.pack("!HH", 2, 0)),
            make_message(struct.pack("!HH", 2, 100)),
            make_message(make_set(2, struct.pack("!HH", 255, 1) + struct.pack("!HH", 8, 4))),
            make_message(make_set(2, struct.pack("!HH", 256, 1))),
            make_message(make_set(2, struct.pack("!HHHH", 256, 1, 0x8008, 4))),
            make_message(make_template([(8, 0)])),
            make_message(make_template(IPV4_FIELDS, options=True, scope_count=0)),
        ]
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.decoder.parse_packet(data, self.ADDR)

    def test_truncated_records_and_variable_lengths_raise(self):
        self.decode(make_template(IPV4_FIELDS))
        for data in (make_record()[:-1], make_record() + b"\1"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.decode(make_set(256, data))
        self.decode(make_template(IPV4_FIELDS + [(82, 65535)]))
        for suffix in (b"", b"\xff", b"\xff\0", b"\x05ab"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.decode(make_set(256, make_record() + suffix))

    def test_invalid_known_ie_lengths_and_oversized_counters_raise(self):
        fields = [(8, 3)] + IPV4_FIELDS[1:]
        payload = make_record()[1:]
        with self.assertRaises(ValueError):
            self.decode(make_template(fields), make_set(256, payload))
        with self.assertRaises(ValueError):
            self.decode(make_template(IPV4_FIELDS), make_set(256, make_record(packets=2**63)))

    def test_netflow_parser_retains_v5_support_and_rejects_truncation(self):
        record = parse_netflow_v5_packet(make_netflow_packet(), self.ADDR)[0]
        self.assertEqual((record["protocol"], record["packets"], record["bytes"]), (6, 2, 200))
        with self.assertRaises(ValueError):
            parse_netflow_v5_packet(make_netflow_packet()[:-1], self.ADDR)

    def test_netcontrol_exact_layouts_and_all_five_message_sizes(self):
        record4 = make_netcontrol_record()
        record6 = make_netcontrol_record("2001:db8::10", "2001:db8::20")
        self.assertEqual((len(record4), len(record6)), (52, 76))
        for ipv4, ipv6, expected_size in (
            ([record4], [], 188), ([], [record6], 212),
            ([record4], [record6], 268),
            ([record4] * 30, [], 1696), ([], [record6] * 30, 2416),
        ):
            with self.subTest(size=expected_size):
                packet = make_netcontrol_message(ipv4, ipv6)
                self.assertEqual(len(packet), expected_size)
                records = self.decoder.parse_packet(packet, self.ADDR, received_at=1700000060)
                self.assertEqual(len(records), len(ipv4) + len(ipv6))
                self.assertEqual(len(self.decoder.templates), 2)
                for record in records:
                    self.assertEqual(
                        (record["packets"], record["bytes"], record["protocol"],
                         record["tos"], record["tcp_flags"], record["last_seen"]),
                        (3, 300, 6, 40, 18, 1700000060),
                    )
                    self.assertEqual((record["start_time"], record["end_time"]), (1700000000, 1700000005))
                    self.assertTrue(record["flow_start"].endswith(".123"))
                    self.assertTrue(record["flow_end"].endswith(".456"))
        self.warn.assert_not_called()

    def test_unexpected_sampling_warns_but_does_not_scale_counts(self):
        record = self.decoder.parse_packet(
            make_netcontrol_message([make_netcontrol_record(sampling_interval=100)]),
            self.ADDR,
        )[0]
        self.assertEqual((record["packets"], record["bytes"]), (3, 300))
        self.assertNotIn("sampling_interval", record)
        self.warn.assert_called_once()
        self.assertIn("without scaling", self.warn.call_args.args[1])

    def test_invalid_sampling_interval_rejects_the_packet(self):
        with self.assertRaises(ValueError):
            self.decoder.parse_packet(
                make_netcontrol_message([make_netcontrol_record(sampling_interval=0)]),
                self.ADDR,
            )

    def test_inverted_export_times_are_preserved_and_warned(self):
        record = self.decoder.parse_packet(
            make_netcontrol_message([make_netcontrol_record(start_ms=1700000010000)]),
            self.ADDR,
        )[0]
        self.assertEqual(record["start_time"], 1700000010)
        self.assertEqual(record["end_time"], 1700000005)
        self.warn.assert_called_once()

    def test_out_of_range_export_times_reject_instead_of_becoming_receipt_time(self):
        with self.assertRaises(ValueError):
            self.decoder.parse_packet(
                make_netcontrol_message([make_netcontrol_record(start_ms=2**64 - 1)]),
                self.ADDR,
            )

    def test_netflow_v5_offsets_for_flags_tos_asns_and_masks(self):
        packet = bytearray(make_netflow_packet())
        struct.pack_into("!BBBBHHBB", packet, 24 + 36, 0, 18, 6, 40, 64500, 64501, 24, 25)
        record = parse_netflow_v5_packet(packet, self.ADDR, received_at=1700000060)[0]
        self.assertEqual(
            (record["tcp_flags"], record["protocol"], record["tos"],
             record["src_as"], record["dst_as"], record["src_mask"], record["dst_mask"]),
            (18, 6, 40, 64500, 64501, 24, 25),
        )
        self.assertEqual((record["start_time"], record["end_time"], record["last_seen"]), (1700000060,) * 3)


if __name__ == "__main__":
    unittest.main()
