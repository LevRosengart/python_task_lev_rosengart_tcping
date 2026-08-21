import random
import struct
from struct import Struct

import pytest

from tcping.tcp_network_filter import TcpNetworkFilter


class TestTcpNetworkFilter:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.expected_resp_source_ip: str = "8.8.8.8"
        self.expected_resp_source_port: int = 443
        self.expected_resp_dest_ip: str = "192.168.0.1"
        self.expected_resp_dest_port: int = 54321
        self.sent_seq = 100
        self.expected_ack = self.sent_seq + 1
        # self.max_seq: int = 2**32
        self.length_and_flags_syn_ack: int = 0b001010_000_00010010
        self.length_and_flags_rst_ack: int = 0b001010_000_00010100
        self.resp_urg_pointer: int = 0
        self.resp_seq: int = random.randint(0, 2**32 - 1)
        self.resp_checksum: int = random.randint(0, 2**16 - 1)  # Checksum should check OS
        self.resp_window_size: int = random.randint(0, 2**16 - 1)
        self.filter = TcpNetworkFilter(
            self.expected_resp_dest_ip,
            self.expected_resp_source_ip,
            self.expected_resp_dest_port,
            self.expected_resp_source_port,
        )
        self.expected_syn_ack_segment: bytes = (
            self.expected_resp_source_port.to_bytes(2)
            + self.expected_resp_dest_port.to_bytes(2)
            + self.resp_seq.to_bytes(4)
            + self.expected_ack.to_bytes(4)
            + self.length_and_flags_syn_ack.to_bytes(2)
            + self.resp_window_size.to_bytes(2)
            + self.resp_checksum.to_bytes(2)
            + self.resp_urg_pointer.to_bytes(2)
        )

    def test_is_valid_correct_syn_ack_segment(self) -> None:
        assert self.filter.is_valid_tcp_response(
            self.expected_syn_ack_segment, self.expected_resp_source_ip, self.sent_seq
        )

    def test_is_valid_with_correct_rst_ack_segment(self) -> None:
        rst_ack_segment: bytearray = bytearray(self.expected_syn_ack_segment)
        Struct("!H").pack_into(rst_ack_segment, 12, self.length_and_flags_rst_ack)
        assert self.filter.is_valid_tcp_response(
            bytes(rst_ack_segment), self.expected_resp_source_ip, self.sent_seq
        )

    def test_is_valid_with_incorrect_resp_source_ip(self) -> None:
        incorrect_ip: str = "1.1.1.1"
        assert not self.filter.is_valid_tcp_response(
            self.expected_syn_ack_segment, incorrect_ip, self.sent_seq
        )

    def test_is_valid_with_incorrect_resp_dest_port(self) -> None:
        incorrect_port: int = 54444
        incorrect_segment: bytearray = bytearray(self.expected_syn_ack_segment)
        struct.Struct("!H").pack_into(incorrect_segment, 2, incorrect_port)
        assert not self.filter.is_valid_tcp_response(
            bytes(incorrect_segment), self.expected_resp_source_ip, self.sent_seq
        )

    def test_is_valid_with_incorrect_resp_source_port(self) -> None:
        incorrect_port: int = 444
        incorrect_segment: bytearray = bytearray(self.expected_syn_ack_segment)
        struct.Struct("!H").pack_into(incorrect_segment, 0, incorrect_port)
        assert not self.filter.is_valid_tcp_response(
            bytes(incorrect_segment), self.expected_resp_source_ip, self.sent_seq
        )
