import random
import socket
from time import perf_counter

from tcping.ip_resolver import IpResolver
from tcping.ping_data import PingData
from tcping.tcp_network_filter import TcpNetworkFilter
from tcping.tcp_segment import TcpSegment


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
        self._timeout: int = timeout
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

    def ping(self, mss: int | None = None, sack_permitted: bool | None = None) -> PingData:
        syn_segment: TcpSegment = TcpSegment(
            self._server_port,
            self._client_port,
            self._server_ip,
            self._client_ip,
            mss=mss,
            sack_permitted=sack_permitted,
        )
        start_time: float = perf_counter()
        self._client_socket.sendto(
            syn_segment.tcp_syn_segment, (self._server_ip, self._server_port)
        )
        while True:
            try:
                ip_packet, server_addr = self._client_socket.recvfrom(self._max_packet_size)
            except (socket.timeout, TimeoutError):
                return PingData(success=False)
            current_time: float = perf_counter()
            if current_time - start_time > self._timeout:
                return PingData(success=False)
            server_addr: str = server_addr[0]
            tcp_received_segment = self._net_filter.get_tcp_segment_from_ip_packet(
                ip_packet
            )
            if self._net_filter.is_valid_tcp_response(
                tcp_received_segment, server_addr, syn_segment.seq_num
            ):
                break
        end_time: float = perf_counter()
        total_time: float = end_time - start_time
        return PingData(success=True, rtt=total_time)
