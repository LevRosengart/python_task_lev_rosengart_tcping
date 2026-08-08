import random
import socket
from struct import Struct


class TcpSegment:
    def __init__(
        self,
        server_port: int,
        client_port: int,
        server_ip: str,
        client_ip: str,
        payload: bytes = b"",
    ) -> None:
        self._server_port: int = server_port
        self._client_port: int = client_port
        self._server_ip: str = socket.gethostbyname(server_ip)
        self._client_ip: str = client_ip
        self._seq_num: int = random.randint(0, 2**32 - 1)
        self._server_bytes_ip: bytes = socket.inet_aton(self._server_ip)
        self._client_bytes_ip: bytes = socket.inet_aton(self._client_ip)
        self._payload: bytes = payload  # Segment body for scalability
        self._tcp_segment_length: int = 20 + len(
            self._payload
        )  # ToDo drop hard-code tcp-length
        self._window_size: int = 2**14
        self._pseudo_header: bytes | None = None
        self._tcp_syn_segment: bytes | None = None
        self._tcp_syn_segment_null_checksum: bytes | None = None
        self._checksum: int | None = None

    @property
    def server_port(self) -> int:
        return self._server_port

    @property
    def client_port(self) -> int:
        return self._client_port

    @property
    def server_ip(self) -> str:
        return self._server_ip

    @property
    def client_ip(self) -> str:
        return self._client_ip

    @property
    def seq_num(self) -> int:
        return self._seq_num

    @property
    def window_size(self) -> int:
        return self._window_size

    @property
    def server_bytes_ip(self) -> bytes:
        return self._server_bytes_ip

    @property
    def client_bytes_ip(self) -> bytes:
        return self._client_bytes_ip

    @property
    def payload(self) -> bytes:
        return self._payload

    @property
    def tcp_segment_length(self) -> int:
        return self._tcp_segment_length

    @property
    def pseudo_header(self) -> bytes:
        if self._pseudo_header is not None:
            return self._pseudo_header
        pseudo_format: str = "!4s4sBBH"
        pseudo_headers: bytes = Struct(pseudo_format).pack(
            self._client_bytes_ip,
            self._server_bytes_ip,
            0,
            socket.IPPROTO_TCP,
            self._tcp_segment_length,
        )
        self._pseudo_header = pseudo_headers
        return pseudo_headers

    @property
    def tcp_syn_segment_without_checksum(self) -> bytes:
        if self._tcp_syn_segment_null_checksum is not None:
            return self._tcp_syn_segment_null_checksum
        segment_format: str = "!HHIIHHHH"
        header_length_in_words: int = 5
        ack_num: int = 0
        syn_flag: int = 1
        mock_checksum: int = 0
        important_info: int = 0
        length_flags_field: int = (header_length_in_words << 12) | (syn_flag << 1)
        tcp_syn_segment_null_checksum: bytes = Struct(segment_format).pack(
            self.client_port,
            self.server_port,
            self.seq_num,
            ack_num,
            length_flags_field,
            self._window_size,
            mock_checksum,
            important_info,
        )
        self._tcp_syn_segment_null_checksum = tcp_syn_segment_null_checksum
        return self._tcp_syn_segment_null_checksum

    @property
    def checksum(self) -> int:
        if self._checksum is not None:
            return self._checksum
        data: bytes = (
            self.pseudo_header + self.tcp_syn_segment_without_checksum + self.payload
        )
        checksum: int = 0
        if len(data) % 2:
            data += b"\x00"
        for i in range(0, len(data), 2):
            chunk: bytes = data[i : i + 2]
            checksum += int.from_bytes(chunk, byteorder="big")
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        self._checksum = (~checksum) & 0xFFFF
        return self._checksum

    @property
    def tcp_syn_segment(self) -> bytes:
        if self._tcp_syn_segment is not None:
            return self._tcp_syn_segment
        null_checksum_segment: bytearray = bytearray(
            self.tcp_syn_segment_without_checksum
        )
        Struct("!H").pack_into(null_checksum_segment, 16, self.checksum)
        self._tcp_syn_segment = bytes(null_checksum_segment)
        return self._tcp_syn_segment
