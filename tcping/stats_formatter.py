from tcping.metrics import PingMetrics


class StatsFormatter:
    def __init__(self):
        pass

    @classmethod
    def format(cls, metrics: PingMetrics) -> str:
        result = f"---\tTCPing\t---\n"
        result += f"Sent packets: {metrics.sent_packets_count}\n"
        result += f"Received packets: {metrics.received_packets_count}\n"
        if metrics.received_packets_count > 0:
            result += f"Avg RTT: {metrics.avg_rtt:.5f}\n"
            result += f"Max RTT: {metrics.max_rtt:.5f}\n"
            result += f"Min RTT: {metrics.min_rtt:.5f}\n"

        return result
