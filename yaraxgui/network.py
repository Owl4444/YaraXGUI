"""Verified TLS transport shared by desktop API clients.

HTTP is an explicit localhost development option. No automatic redirects or
HTTP fallback are permitted for requests that may carry credentials.
"""
import errno
import ipaddress
import os
import socket
import ssl
from urllib.error import URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


def _loopback(host):
    # localhost is resolved by the OS; a certificate is still required when TLS
    # is selected. Do not treat private network ranges as secure transports.
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def api_url(url, get_setting=None):
    get = get_setting or (lambda key, default: default)
    value = url.strip().rstrip('/')
    if not value:
        raise ValueError('Set the YaraXGUI server URL in Settings')
    if '://' not in value:
        value = 'https://' + value
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Use an HTTP(S) server URL without credentials, query, or fragment')
    parsed.port  # Validate malformed ports before constructing a request.
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address is not None and address.is_unspecified:
        raise ValueError('Use the configured server hostname or reachable IP in the URL; 0.0.0.0 and :: are listen addresses, not server destinations')
    if get('api_https_enabled', True):
        parsed = parsed._replace(scheme='https')
    elif parsed.scheme == 'http' and not _loopback(parsed.hostname):
        raise ValueError('Plain HTTP is only supported for localhost development; use HTTPS for remote servers')
    return urlunsplit(parsed)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirect refused to protect credentials. Configure the final HTTPS API URL in Settings.')


def tls_context(ca_file=''):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
    return context


def secure_urlopen(request, *, timeout=10, ca_file='', allow_loopback_http=False):
    url = request.full_url if isinstance(request, Request) else request
    parsed = urlsplit(url)
    if parsed.username or parsed.password or not parsed.hostname or parsed.fragment:
        raise ValueError('Invalid API URL')
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and allow_loopback_http and _loopback(parsed.hostname)):
        raise ValueError('HTTPS is required for this connection. Configure an HTTPS endpoint.')
    opener = build_opener(HTTPSHandler(context=tls_context(ca_file)), NoRedirect())
    return opener.open(request, timeout=timeout)


def api_urlopen(request, get_setting=None, *, timeout=10):
    get = get_setting or (lambda key, default: default)
    # Callers normalize the base URL before adding paths/queries. Check the
    # resulting transport again so no call site can accidentally downgrade it.
    return secure_urlopen(request, timeout=timeout,
                          ca_file=get('api_ca_file', ''),
                          allow_loopback_http=not get('api_https_enabled', True))


def connection_error_message(error, url):
    """Explain transport failures without echoing request paths or credentials.

    Keep this at the UI boundary: callers of the transport still receive the
    original exception, and certificate failures never trigger insecure retries.
    """
    parsed = urlsplit(url)
    host = parsed.hostname or 'server'
    authority = f'[{host}]' if ':' in host else host
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    endpoint = f'{parsed.scheme}://{authority}:{port}'
    reason = error.reason if isinstance(error, URLError) else error
    code = getattr(reason, 'winerror', None) or getattr(reason, 'errno', None)
    if isinstance(reason, FileNotFoundError):
        message = 'The configured CA certificate file was not found. Update Additional CA (PEM) in Settings on this computer.'
    elif isinstance(reason, PermissionError):
        message = f'Permission denied while connecting to {endpoint}. Check CA file permissions and local firewall policy.'
    elif isinstance(reason, ssl.SSLCertVerificationError):
        verification = getattr(reason, 'verify_code', None)
        if verification in (62, 64):
            advice = 'The certificate does not cover this hostname/IP. Use the certificate hostname or correct the server certificate.'
        elif verification in (9, 10):
            advice = 'The certificate is expired or not yet valid. Check the system clock and renew the server certificate.'
        else:
            advice = ('The certificate could not be verified. Check the server certificate chain; '
                      'for a private CA, select its trusted CA certificate under Additional CA (PEM) in Settings.')
        message = f'TLS certificate verification failed for {endpoint}. {advice}'
    elif isinstance(reason, ssl.SSLError):
        if getattr(reason, 'reason', None) == 'TLSV1_ALERT_INTERNAL_ERROR':
            message = (f'The TLS endpoint at {endpoint} returned an internal error during the handshake '
                       '(TLSV1_ALERT_INTERNAL_ERROR). With Docker Compose, use the hostname or IP configured '
                       'in YARAXGUI_DOMAIN and check Caddy logs for certificate provisioning or '
                       'hostname selection errors. This happens before API key authentication.')
        else:
            message = (f'TLS negotiation failed with {endpoint}. Check that this port serves HTTPS '
                       'and that the server supports TLS 1.2 or newer.')
    elif isinstance(reason, socket.gaierror) or code == 11001:
        message = f'Cannot resolve {host}. Check the server hostname, DNS and any configured proxy.'
    elif isinstance(reason, ConnectionRefusedError) or code in (errno.ECONNREFUSED, 10061):
        message = f'Connection refused by {endpoint}. Check that the server is running and its HTTPS port is published.'
    elif isinstance(reason, TimeoutError) or code in (errno.ETIMEDOUT, 10060):
        message = f'Connection to {endpoint} timed out. Check server health, firewall, network and proxy settings.'
    elif isinstance(reason, ConnectionResetError) or code in (errno.ECONNRESET, 10054):
        message = f'Connection to {endpoint} was reset. Check the HTTPS listener, proxy and server logs.'
    else:
        # Arbitrary reason strings can contain URLs, proxy credentials or queries.
        detail = f' (OS error {code})' if isinstance(code, int) else ''
        message = f'Could not connect to {endpoint}{detail}. Check the server URL, network, proxy and server logs.'
    if port == 7777:
        message += (f' With the supplied Docker Compose setup, use https://{authority} '
                    '(port 443); port 7777 is internal. Keep a custom port only if you configured a public HTTPS listener there.')
    return message


def mwdb_urlopen(request, *, timeout=10):
    return secure_urlopen(request, timeout=timeout,
                          ca_file=os.environ.get('YARAXGUI_MWDB_CA_FILE', ''))


def mwdb_session():
    """mwdblib transport with the same HTTPS/no-redirect credential policy."""
    import requests
    class Session(requests.Session):
        def send(self, request, **kwargs):
            parsed = urlsplit(request.url)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError('MWDB requires an HTTPS endpoint')
            kwargs['verify'] = os.environ.get('YARAXGUI_MWDB_CA_FILE') or True
            kwargs['allow_redirects'] = False
            kwargs['timeout'] = kwargs.get('timeout') or 30
            response = super().send(request, **kwargs)
            if 300 <= response.status_code < 400:
                response.close()
                raise ValueError('MWDB redirects are disabled; configure the final HTTPS API URL')
            return response
    return Session()


def safe_sample_name(name):
    """A remote filename is a display hint, never a local path/device name."""
    import re
    basename = str(name).replace("\\", "/").split("/")[-1]
    return 'sample_' + (re.sub(r'[^A-Za-z0-9._-]', '_', basename)[:160].strip('. ') or 'download')


def save_download(directory, name, data):
    """Create a unique file; never follow or overwrite an existing target."""
    from pathlib import Path
    import uuid
    target = Path(directory) / (uuid.uuid4().hex[:12] + '_' + safe_sample_name(name))
    with target.open('xb') as stream:
        stream.write(data)
    return target
