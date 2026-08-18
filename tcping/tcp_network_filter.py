class TcpNetworkFilter:
    def __init__(
        self,
        client_source_ip: str,
        client_dest_ip: str,
        client_source_port: int,
        client_dest_port: int,
    ):
        self._resp_dest_ip: str = client_source_ip
        self._resp_dest_port: int = client_source_port
        self._resp_source_ip: str = client_dest_ip
        self._resp_source_port: int = client_dest_port

    def is_valid_tcp_response(
        self, segment: bytes, server_ip: str, sent_seq_num: int
    ) -> bool:
        if not self._is_valid_tcp_response_dest(segment, server_ip):
            return False
        flags: dict[str, bool] = self._get_syn_ack_rst_flags(segment)
        if flags["ack"]:
            received_ack_num: int = int.from_bytes(segment[8:12], byteorder="big")
            return received_ack_num == (sent_seq_num + 1) & 0xFFFF_FFFF

        return True

    @staticmethod
    def get_tcp_segment_from_ip_packet(packet: bytes) -> bytes:
        if len(packet) < 20:
            return b""
        version: int = packet[0] >> 4
        if version != 4:
            return b""
        ihl: int = packet[0] & 0x0F  # In 32-bit words
        ip_header_len_in_bytes: int = ihl * 4

        return packet[ip_header_len_in_bytes:]

    def _is_valid_tcp_response_dest(self, segment: bytes, server_ip: str) -> bool:
        if server_ip != self._resp_source_ip:
            return False
        received_resp_source_port: int = int.from_bytes(segment[:2], byteorder="big")
        received_resp_dest_port: int = int.from_bytes(segment[2:4], byteorder="big")
        return (
            received_resp_dest_port == self._resp_dest_port
            and received_resp_source_port == self._resp_source_port
        )

    @classmethod
    def _get_syn_ack_rst_flags(cls, segment: bytes) -> dict[str, bool]:
        flags_byte = segment[13]
        is_ack: bool = bool(flags_byte & 0x10)
        is_rst: bool = bool(flags_byte & 0x04)
        is_syn: bool = bool(flags_byte & 0x02)
        return {"ack": is_ack, "syn": is_syn, "rst": is_rst}
