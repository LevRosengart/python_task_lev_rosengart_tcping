import socket


class IpResolver:
    def __init__(self) -> None:
        self._mock_ip: str = "8.8.8.8"
        self._mock_port: int = 67
        self._client_ip: str | None = None

    @property
    def client_ip(self) -> str:
        if self._client_ip is None:
            self._client_ip = self._get_client_ip()
        return self._client_ip

    def _get_client_ip(self) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
            conn.connect((self._mock_ip, self._mock_port))
            return conn.getsockname()[0]
