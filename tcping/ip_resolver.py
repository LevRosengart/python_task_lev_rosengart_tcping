import socket


class IpResolver:
    def __init__(self):
        self._client_ip: str | None = None

    @property
    def client_ip(self) -> str:
        if self._client_ip is None:
            self._client_ip = self._get_client_ip()
        return self._client_ip

    @staticmethod
    def _get_client_ip() -> str:
        mock_server_ip: str = "1.1.1.1"
        mock_server_port = 1234
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
            conn.connect((mock_server_ip, mock_server_port))
            return conn.getsockname()[0]
