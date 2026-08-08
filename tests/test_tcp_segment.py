import pytest
from socket import IPPROTO_TCP

from tcping.tcp_segment import TcpSegment


class TestTcpSegment:
    MOCK_SERVER_PORT: int = 80
    MOCK_CLIENT_PORT: int = 1024
    MOCK_SERVER_IP: str = "8.8.8.8"
    MOCK_CLIENT_IP: str = "192.168.0.1"

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
        assert segment.server_bytes_ip == b"\x08\x08\x08\x08"
        assert segment.client_bytes_ip == b"\xc0\xa8\x00\x01"

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
        protocol: bytes = IPPROTO_TCP.to_bytes(1, byteorder="big")
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
