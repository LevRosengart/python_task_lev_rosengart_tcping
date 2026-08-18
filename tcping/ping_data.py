from dataclasses import dataclass


@dataclass(frozen=True)
class PingData:
    success: bool
    rtt: float | int = 0
