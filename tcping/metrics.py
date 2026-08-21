from tcping.ping_data import PingData


class PingMetrics:
    def __init__(self) -> None:
        self._max_rtt: float | None = None
        self._min_rtt: float | None = None
        self._sum_rtt: float = 0.0
        self._sent_packets_count: int = 0
        self._received_packets_count: int = 0

    def record(self, ping_info: PingData) -> None:
        self._sent_packets_count += 1
        if ping_info.success:
            self._received_packets_count += 1
            self._max_rtt = (
                max(self._max_rtt, ping_info.rtt) if self._max_rtt is not None else ping_info.rtt
            )
            self._min_rtt = (
                min(self._min_rtt, ping_info.rtt) if self._min_rtt is not None else ping_info.rtt
            )
            self._sum_rtt += ping_info.rtt

    @property
    def max_rtt(self) -> float | None:
        return self._max_rtt

    @property
    def min_rtt(self) -> float | None:
        return self._min_rtt

    @property
    def avg_rtt(self) -> float | None:
        return (
            self._sum_rtt / self._received_packets_count
            if self.received_packets_count > 0
            else None
        )

    @property
    def sent_packets_count(self) -> int:
        return self._sent_packets_count

    @property
    def received_packets_count(self) -> int:
        return self._received_packets_count
