import pytest

from tcping.ping_data import PingData
from tcping.metrics import PingMetrics


class TestPingMetrics:
    def test_empty_metrics(self) -> None:
        metrics = PingMetrics()

        assert metrics.sent_packets_count == 0
        assert metrics.received_packets_count == 0
        assert metrics.min_rtt is None
        assert metrics.max_rtt is None
        assert metrics.avg_rtt is None

    def test_single_successful_ping(self) -> None:
        metrics = PingMetrics()

        metrics.record(PingData(success=True, rtt=0.1))

        assert metrics.sent_packets_count == 1
        assert metrics.received_packets_count == 1
        assert metrics.min_rtt == pytest.approx(0.1, abs=1e-6)
        assert metrics.max_rtt == pytest.approx(0.1, abs=1e-6)
        assert metrics.max_rtt == pytest.approx(0.1, abs=1e-6)
        assert metrics.avg_rtt == pytest.approx(0.1, abs=1e-6)

    def test_multiple_successful_pings(self) -> None:
        metrics = PingMetrics()

        metrics.record(PingData(success=True, rtt=0.1))
        metrics.record(PingData(success=True, rtt=0.3))
        metrics.record(PingData(success=True, rtt=0.2))

        assert metrics.sent_packets_count == 3
        assert metrics.received_packets_count == 3
        assert metrics.min_rtt == pytest.approx(0.1, abs=1e-6)
        assert metrics.max_rtt == pytest.approx(0.3, abs=1e-6)
        assert metrics.avg_rtt == pytest.approx(0.2, abs=1e-6)

    def test_lost_ping(self) -> None:
        metrics = PingMetrics()

        metrics.record(PingData(success=False))

        assert metrics.sent_packets_count == 1
        assert metrics.received_packets_count == 0
        assert metrics.min_rtt is None
        assert metrics.max_rtt is None
        assert metrics.avg_rtt is None

    def test_successful_and_lost_pings(self) -> None:
        metrics = PingMetrics()

        metrics.record(PingData(success=True, rtt=0.1))
        metrics.record(PingData(success=False))
        metrics.record(PingData(success=True, rtt=0.3))

        assert metrics.sent_packets_count == 3
        assert metrics.received_packets_count == 2
        assert metrics.min_rtt == pytest.approx(0.1, abs=1e-6)
        assert metrics.max_rtt == pytest.approx(0.3, abs=1e-6)
        assert metrics.avg_rtt == pytest.approx(0.2, abs=1e-6)
