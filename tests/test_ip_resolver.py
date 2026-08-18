import pytest

from tcping.ip_resolver import IpResolver
from pytest_mock import MockerFixture
from unittest.mock import MagicMock


class TestIpResolver:
    expected_client_ip: str = "192.168.0.10"
    mock_client_port: int = 12345
    mock_server_ip: str = "1.1.1.1"
    mock_server_port: int = 1234

    @pytest.fixture
    def mocked_resolver_socket(
        self, mocker: MockerFixture
    ) -> tuple[IpResolver, MagicMock]:
        mock_socket_module: MagicMock = mocker.patch("tcping.ip_resolver.socket")
        mock_socket_instance: MagicMock = (
            mock_socket_module.socket.return_value.__enter__.return_value
        )
        mock_socket_instance.getsockname.return_value = (
            self.expected_client_ip,
            self.mock_client_port,
        )
        resolver: IpResolver = IpResolver()
        return resolver, mock_socket_instance

    def test_get_client_ip(self, mocked_resolver_socket) -> None:
        mocked_resolver, mock_socket_instance = mocked_resolver_socket
        result: str = mocked_resolver.client_ip

        assert result == self.expected_client_ip
        mock_socket_instance.connect.assert_called_once_with(
            (self.mock_server_ip, self.mock_server_port)
        )

    def test_client_ip_with_cached_ip(self, mocked_resolver_socket) -> None:
        mocked_resolver, mock_socket_instance = mocked_resolver_socket
        first_result_ip = mocked_resolver.client_ip
        second_result_ip = mocked_resolver.client_ip

        assert first_result_ip == second_result_ip == self.expected_client_ip
        # Despite the client_ip property being accessed twice,
        # connect() should be called only once, and client_ip should be stored
        mock_socket_instance.connect.assert_called_once_with(
            (self.mock_server_ip, self.mock_server_port)
        )
