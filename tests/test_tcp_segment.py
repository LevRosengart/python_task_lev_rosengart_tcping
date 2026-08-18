import random
from struct import Struct

import pytest
import socket

from tcping.tcp_segment import TcpSegment


class TestTcpSegment:
    MOCK_SERVER_PORT: int = 80
    MOCK_CLIENT_PORT: int = 1024
    MOCK_SERVER_IP: str = "8.8.8.8"
    MOCK_CLIENT_IP: str = "192.168.0.1"
    MIN_PORT_NUM: int = 1
    MAX_PORT_NUM: int = 2**16 - 1

    @pytest.fixture
    def segment(self) -> TcpSegment:
        return TcpSegment(
            server_port=self.MOCK_SERVER_PORT,
            client_port=self.MOCK_CLIENT_PORT,
            server_ip=self.MOCK_SERVER_IP,
            client_ip=self.MOCK_CLIENT_IP,
        )

    def test_init_simple_attrs(self, segment: TcpSegment) -> None:
        assert segment.server_port == self.MOCK_SERVER_PORT
        assert segment.server_ip == self.MOCK_SERVER_IP
        assert 0 <= segment.seq_num <= 2**32 - 1

    def test_init_bytes_ip(self, segment: TcpSegment) -> None:
        assert segment.server_bytes_ip == socket.inet_aton(self.MOCK_SERVER_IP)
        assert segment.client_bytes_ip == socket.inet_aton(self.MOCK_CLIENT_IP)

    def test_pseudo_header(self, segment: TcpSegment) -> None:
        # Calculating pseudo headers:
        # Source address = C0 A8 00 01"
        # Destination address = 08 08 08 08
        # Placeholder = 00
        # Protocol (TCP = 6) = 06
        # Length of the TCP segment = 14

        source_address: bytes = segment.client_bytes_ip
        dest_address: bytes = segment.server_bytes_ip
        placeholder: bytes = b"\x00"
        protocol: bytes = socket.IPPROTO_TCP.to_bytes(1, byteorder="big")
        segment_length: bytes = segment.tcp_segment_length.to_bytes(2, byteorder="big")
        expected_pseudo_header: bytes = (
            source_address + dest_address + placeholder + protocol + segment_length
        )

        assert segment.pseudo_header == expected_pseudo_header

    def test_tcp_syn_null_checksum(self, segment: TcpSegment) -> None:
        # |    Source port: 04 00   |    Dest Port: 00 50   |
        # |        Sequence number: self.seq_num            |
        # |        Acknowledgement number: 00 00 00 00      |
        # |   HLen: 5 |000|000000010| Window size: 40 00    |
        # |   Null checksum: 00 00  | Urgent pointer: 00 00 |
        source_port: bytes = segment.client_port.to_bytes(
            2, byteorder="big"
        )  # b"\x04\x00"
        dest_port: bytes = segment.server_port.to_bytes(
            2, byteorder="big"
        )  # b"\x00\x50"
        seq_num: bytes = segment.seq_num.to_bytes(4, byteorder="big")
        ack_num: bytes = b"\x00" * 4
        binary_length_flags: int = 0b0101_0000_0000_0010
        header_length_flags: bytes = binary_length_flags.to_bytes(2, byteorder="big")
        window_size: bytes = segment._window_size.to_bytes(
            2, byteorder="big"
        )  # b"\x40\x00"
        # assert int.from_bytes(window_size, byteorder="big") == segment._window_size
        null_checksum: bytes = b"\x00\x00"
        urg_pointer: bytes = b"\x00\x00"
        expected_syn: bytes = (
            source_port
            + dest_port
            + seq_num
            + ack_num
            + header_length_flags
            + window_size
            + null_checksum
            + urg_pointer
        )
        assert expected_syn == segment.tcp_syn_segment_without_checksum

    @staticmethod
    def generate_random_ip() -> str:
        result_ip: str = ""
        octet_count: int = 4
        for i in range(octet_count):
            result_ip += str(random.randint(0, 255))
            if i != octet_count - 1:
                result_ip += "."

        return result_ip

    def test_tcp_checksum_range(self) -> None:
        for i in range(50):
            max_port_num: int = 2**16 - 1
            max_expected_checksum: int = 2**16 - 1
            min_expected_checksum: int = 0
            min_port_num: int = 1
            server_ip: str = self.generate_random_ip()
            client_ip: str = self.generate_random_ip()
            server_port: int = random.randint(min_port_num, max_port_num)
            client_port: int = random.randint(min_port_num, max_port_num)
            segment: TcpSegment = TcpSegment(
                server_port, client_port, server_ip, client_ip
            )
            assert min_expected_checksum <= segment.checksum <= max_expected_checksum

    def test_checksum(self) -> None:
        for i in range(50):
            server_ip: str = self.generate_random_ip()
            client_ip: str = self.generate_random_ip()
            server_port: int = random.randint(self.MIN_PORT_NUM, self.MAX_PORT_NUM)
            client_port: int = random.randint(self.MIN_PORT_NUM, self.MAX_PORT_NUM)
            segment: TcpSegment = TcpSegment(
                server_port, client_port, server_ip, client_ip
            )
            null_checksum_field_segment: bytearray = bytearray(
                segment.tcp_syn_segment_without_checksum
            )
            checksum: int = TcpSegment.calculate_checksum(null_checksum_field_segment)
            Struct("!H").pack_into(null_checksum_field_segment, 16, checksum)
            new_checksum: int = TcpSegment.calculate_checksum(
                bytes(null_checksum_field_segment)
            )
            assert new_checksum == 0

    def test_tcp_syn_segment(self, segment: TcpSegment) -> None:
        expected_tcp_segment: bytearray = bytearray(segment.tcp_syn_segment_without_checksum)
        checksum: int = segment.checksum
        Struct("!H").pack_into(expected_tcp_segment, 16, checksum)
        assert bytes(expected_tcp_segment) == segment.tcp_syn_segment
