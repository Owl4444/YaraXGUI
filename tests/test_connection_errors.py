"""Connection diagnostics across Linux/Windows without credential disclosure."""
import errno
import socket
import ssl
from urllib.error import URLError

import pytest

from yaraxgui.network import connection_error_message


@pytest.mark.parametrize('reason,expected', [
    (socket.gaierror(socket.EAI_NONAME, 'missing'), 'Cannot resolve'),
    (OSError(11001, 'Windows DNS failure'), 'Cannot resolve'),
    (ConnectionRefusedError(errno.ECONNREFUSED, 'refused'), 'Connection refused'),
    (OSError(10061, 'Windows refused'), 'Connection refused'),
    (TimeoutError('read timed out'), 'timed out'),
    (OSError(10060, 'Windows timeout'), 'timed out'),
    (ConnectionResetError(errno.ECONNRESET, 'reset'), 'was reset'),
    (OSError(10054, 'Windows reset'), 'was reset'),
    (ssl.SSLError(1, 'WRONG_VERSION_NUMBER'), 'Check that this port serves HTTPS'),
    (FileNotFoundError('private CA'), 'CA certificate file was not found'),
    (PermissionError('private CA'), 'Check CA file permissions'),
    ('proxy credentials: sensitive', 'Could not connect'),
])
def test_connection_reason_classification(reason, expected):
    for error in (reason, URLError(reason)):
        message = connection_error_message(error, 'https://example.test')
        assert expected in message
        assert 'sensitive' not in message


@pytest.mark.parametrize('code,expected', [
    (62, 'does not cover this hostname/IP'),
    (64, 'does not cover this hostname/IP'),
    (9, 'expired or not yet valid'),
    (10, 'expired or not yet valid'),
    (18, 'Additional CA (PEM)'),
    (20, 'Additional CA (PEM)'),
])
def test_certificate_remediation(code, expected):
    error = ssl.SSLCertVerificationError(1, 'verification failed')
    error.verify_code = code
    assert expected in connection_error_message(URLError(error), 'https://example.test')


def test_docker_port_hint_preserves_ipv6_and_redacts_credentials():
    message = connection_error_message(URLError('secret error'),
        'https://user:password@[::1]:7777/private?api_key=secret')
    assert 'https://[::1]:7777' in message
    assert 'use https://[::1] (port 443)' in message
    for secret in ('user', 'password', 'private', 'api_key', 'secret'):
        assert secret not in message
    assert '7777 is internal' not in connection_error_message(
        TimeoutError(), 'https://example.test:8443')


@pytest.mark.parametrize('url', ['https://0.0.0.0', 'https://[::]', 'https://[0:0:0:0:0:0:0:0]:443'])
def test_listen_address_is_not_a_client_destination(url):
    from yaraxgui.network import api_url
    with pytest.raises(ValueError, match='listen addresses'):
        api_url(url)
