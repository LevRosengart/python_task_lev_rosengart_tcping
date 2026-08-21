import time
from argparse import ArgumentParser

from tcping.metrics import PingMetrics
from tcping.ping_data import PingData
from tcping.stats_formatter import StatsFormatter
from tcping.tcp_pinger import TcpPinger


def main() -> None:
    arg_parser: ArgumentParser = ArgumentParser(
        description="Tcping. Measures RTT (Round-Trip Time)from user client to specified port."
    )

    arg_parser.add_argument("host", type=str, help="Hostname or ip")
    arg_parser.add_argument("port", type=int, help="Checked port")
    arg_parser.add_argument(
        "-n", "--pings_count", type=int, help="Pings count, default = 1", default=1
    )
    arg_parser.add_argument(
        "-t", "--timeout", type=float, help="Timeout in sec, default = 3", default=3
    )
    arg_parser.add_argument(
        "-i",
        "--interval",
        type=float,
        help="Interval between pings in sec, default = 0.5",
        default=0.5,
    )
    args = arg_parser.parse_args()

    tcp_pinger: TcpPinger = TcpPinger(
        args.host,
        args.port,
        timeout=args.timeout,
    )
    metrics: PingMetrics = PingMetrics()
    print(
        f"Pinging {args.host}:{args.port} with {args.pings_count} pings, timeout {args.timeout} sec, interval {args.interval} sec"
    )
    for ping_count in range(1, args.pings_count + 1):
        try:
            ping_info: PingData = tcp_pinger.ping(mss=1452, sack_permitted=True)
            metrics.record(ping_info)
        except Exception as e:  # NOQA
            print("Unexpected error")
        else:
            if ping_info.success:
                print(f"PING {ping_count}\tRound-Trip Time: {ping_info.rtt:.5f} sec")
            else:
                print(f"PING {ping_count}\tPacket is loss")
        if ping_count < args.pings_count:
            time.sleep(args.interval)

    print(StatsFormatter.format(metrics))


if __name__ == "__main__":
    main()
