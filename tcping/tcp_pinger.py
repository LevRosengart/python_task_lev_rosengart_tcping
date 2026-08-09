import socket
import random
from time import perf_counter
from tcping.ip_resolver import IpResolver
from tcping.tcp_segment import TcpSegment
from tcping.tcp_network_filter import TcpNetworkFilter


class TcpPinger:
    def __init__(
        self,
        server_ip: str,
        server_port: int,
        timeout: int = 3,
    ):
        self._ip_resolver: IpResolver = IpResolver()
        self._server_ip: str = socket.gethostbyname(server_ip)
        self._server_port: int = server_port
        self._client_port: int | None = None
        self._client_ip: str = (
            self._ip_resolver.client_ip if server_ip != "127.0.0.1" else "127.0.0.1"
        )
        self._client_socket: socket.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )
        self._client_socket.settimeout(timeout)
        self._client_port: int = random.randint(49152, 65535)
        self._net_filter: TcpNetworkFilter = TcpNetworkFilter(
            self._client_ip, self._server_ip, self._client_port, self._server_port
        )
        self._max_packet_size: int = 2**16 - 1

    def ping(self) -> float:
        syn_segment: TcpSegment = TcpSegment(
            self._server_port, self._client_port, self._server_ip, self._client_ip
        )
        start_time: float = perf_counter()
        self._client_socket.sendto(
            syn_segment.tcp_syn_segment, (self._server_ip, self._server_port)
        )
        while True:
            ip_packet, served_addr = self._client_socket.recvfrom(self._max_packet_size)
            served_addr: str = served_addr[0]
            tcp_received_segment = self._net_filter.get_tcp_segment_from_ip_packet(
                ip_packet
            )
            if self._net_filter.is_valid_tcp_response(
                tcp_received_segment, served_addr, syn_segment.seq_num
            ):
                break
        end_time: float = perf_counter()
        total_time: float = end_time - start_time

        return total_time
