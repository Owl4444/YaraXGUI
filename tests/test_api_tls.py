import http.server
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.error import URLError, HTTPError
from urllib.request import Request

import pytest

from yaraxgui.network import api_url, api_urlopen, secure_urlopen, tls_context, mwdb_session


@pytest.fixture(scope='module')
def certificate(tmp_path_factory):
    folder = tmp_path_factory.mktemp('tls')
    key, cert = folder / 'key.pem', folder / 'cert.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                   check=True, capture_output=True)
    return key, cert


@pytest.fixture
def tls_site(certificate):
    key, cert = certificate
    seen = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', 'http://127.0.0.1:1/stolen')
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'ok')
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'https://localhost:{server.server_port}', cert, seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_url_normalization_no_silent_http_fallback():
    assert api_url('http://host:7777/api') == 'https://host:7777/api'
    assert api_url('host') == 'https://host'
    dev = {'api_https_enabled': False}.get
    assert api_url('http://127.0.0.1:7777', dev) == 'http://127.0.0.1:7777'
    for url in ['file:///etc/passwd', 'https://user:secret@host', 'https://host/?key=abc', 'https://host/#fragment']:
        with pytest.raises(ValueError):
            api_url(url)
    with pytest.raises(ValueError):
        api_url('http://192.168.0.1:7777', dev)
    with pytest.raises(ValueError):
        api_urlopen('http://localhost:7777')


def test_custom_ca_verification_hostname_and_redirects(tls_site):
    url, cert, seen = tls_site
    settings = {'api_ca_file':str(cert)}.get
    req = Request(url, headers={'X-API-Key':'test-key'})
    with api_urlopen(req, settings) as response:
        assert response.read() == b'ok'
    with pytest.raises(URLError):
        api_urlopen(req)  # Untrusted certificate must fail, never retry with HTTP.
    with pytest.raises(URLError):
        api_urlopen(url.replace('localhost', '127.0.0.1'), settings)
    with pytest.raises(ValueError, match='Redirect refused'):
        api_urlopen(Request(url + '/redirect', headers={'X-API-Key':'test-key'}), settings)
    assert seen == ['/', '/redirect']
    context = tls_context(str(cert))
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_mwdb_credentials_cannot_redirect(tls_site):
    from api.mwdb import NoRedirect
    from urllib.request import build_opener, HTTPSHandler
    url, cert, _ = tls_site
    opener = build_opener(HTTPSHandler(context=tls_context(str(cert))), NoRedirect())
    with pytest.raises(ValueError, match='redirects are disabled'):
        opener.open(Request(url+'/redirect', headers={'Authorization':'Bearer secret'}))
    with pytest.raises(ValueError, match='HTTPS'):
        secure_urlopen('http://192.168.0.1/api')
    with mwdb_session() as session:
        with pytest.raises(ValueError, match='HTTPS'):
            session.get('http://127.0.0.1:1', headers={'Authorization':'Bearer secret'})


def test_settings_default_https_and_private_ca(app, certificate):
    from yaraxgui.ui.settings import SettingsDialog
    _, cert = certificate
    dialog = SettingsDialog(api_server_url='http://localhost:7777', api_ca_file=str(cert))
    assert dialog.api_https_enabled()
    assert dialog.api_server_url() == 'https://localhost:7777'
    assert dialog.api_ca_file() == str(cert)
    dialog._api_https_check.setChecked(False)
    assert dialog.api_server_url() == 'http://localhost:7777'
    dialog.close()


def test_real_public_mode_tls_server(certificate, tmp_path):
    key, cert = certificate
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    root = Path(__file__).resolve().parents[1]
    key_value = 'test-only-public-server-key-0123456789abcdef'
    env = dict(os.environ, YARAXGUI_DEV_MODE='0', YARAXGUI_REQUIRE_HTTPS='1',
               YARAXGUI_API_KEY=key_value, YARAXGUI_ALLOWED_HOSTS='localhost,127.0.0.1',
               YARAXGUI_TRUSTED_PROXIES='', YARAXGUI_SSL_CERTFILE=str(cert),
               YARAXGUI_SSL_KEYFILE=str(key), YARAXGUI_HOST='127.0.0.1',
               YARAXGUI_PORT=str(port), YARAXGUI_REPO_DB=str(tmp_path/'rules.db'),
               YARAXGUI_UPLOAD_DIR=str(tmp_path/'uploads'), YARAXGUI_ALLOWED_ROOTS='')
    process = subprocess.Popen([sys.executable, '-m', 'api.server'], cwd=root, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    settings = {'api_ca_file':str(cert)}.get
    url = f'https://localhost:{port}'
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail(process.stdout.read())
            try:
                with api_urlopen(url+'/health', settings, timeout=.5) as response:
                    assert response.read() == b'{"status":"ok"}'
                    break
            except URLError:
                time.sleep(.05)
        else:
            pytest.fail('TLS server did not start')
        with pytest.raises(HTTPError) as missing:
            api_urlopen(url+'/repo/stats', settings)
        assert missing.value.code == 403
        with api_urlopen(Request(url+'/repo/stats', headers={'X-API-Key':key_value}), settings) as response:
            assert response.status == 200
            assert 'max-age=' in response.headers['Strict-Transport-Security']
        with pytest.raises(HTTPError) as docs:
            api_urlopen(Request(url+'/openapi.json', headers={'X-API-Key':key_value}), settings)
        assert docs.value.code == 404
        with pytest.raises(URLError):
            api_urlopen(url+'/health')
    finally:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


def test_automatic_download_names_cannot_escape_or_overwrite(tmp_path):
    from yaraxgui.network import save_download
    outside = tmp_path.parent / 'protected-file'
    outside.write_bytes(b'original')
    existing = tmp_path / 'sample_protected-file'
    existing.symlink_to(outside)
    first = save_download(tmp_path, '../protected-file', b'sample')
    second = save_download(tmp_path, r'..\CON:stream', b'sample2')
    assert first.parent == second.parent == tmp_path
    assert ':' not in second.name and second.name != 'CON'
    assert first.read_bytes() == b'sample'
    assert outside.read_bytes() == b'original'


def test_mwdb_private_ca_applies_to_both_desktop_transports(tls_site, monkeypatch):
    import requests
    from yaraxgui.network import mwdb_urlopen
    url, cert, _ = tls_site
    monkeypatch.setenv('YARAXGUI_MWDB_CA_FILE', str(cert))
    with mwdb_urlopen(url) as response:
        assert response.read() == b'ok'
    with mwdb_session() as session:
        assert session.get(url).content == b'ok'
        with pytest.raises(ValueError, match='redirects are disabled'):
            session.get(url + '/redirect')
    monkeypatch.delenv('YARAXGUI_MWDB_CA_FILE')
    with mwdb_session() as session:
        with pytest.raises(requests.exceptions.SSLError):
            session.get(url, verify=False)  # Call sites cannot disable verification.


def test_real_certificate_failure_has_actionable_diagnostic(tls_site):
    from yaraxgui.network import connection_error_message

    url, cert, seen = tls_site
    with pytest.raises(URLError) as untrusted:
        api_urlopen(url)
    assert 'Additional CA (PEM)' in connection_error_message(untrusted.value, url)
    wrong_host = url.replace('localhost', '127.0.0.1')
    with pytest.raises(URLError) as mismatch:
        api_urlopen(wrong_host, {'api_ca_file': str(cert)}.get)
    assert 'does not cover this hostname/IP' in connection_error_message(mismatch.value, wrong_host)
    assert seen == []  # Authentication headers cannot be sent after a failed handshake.
    with api_urlopen(url, {'api_ca_file': str(cert)}.get) as response:
        assert response.read() == b'ok'


def test_real_tls_internal_alert_explains_server_failure(certificate):
    from yaraxgui.network import connection_error_message

    key, cert = certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.sni_callback = lambda *args: ssl.ALERT_DESCRIPTION_INTERNAL_ERROR
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(5)
        url = f'https://localhost:{listener.getsockname()[1]}'
        server_errors = []

        def reject_handshake():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(5)
                    with context.wrap_socket(conn, server_side=True):
                        pass
            except OSError as error:
                server_errors.append(error)

        thread = threading.Thread(target=reject_handshake, daemon=True)
        thread.start()
        try:
            with pytest.raises(URLError) as failure:
                api_urlopen(url, timeout=3)
            assert failure.value.reason.reason == 'TLSV1_ALERT_INTERNAL_ERROR'
            message = connection_error_message(failure.value, url)
            assert 'TLS endpoint' in message
            assert 'YARAXGUI_DOMAIN' in message
            assert 'check Caddy logs' in message
            assert 'before API key authentication' in message
            assert 'supports TLS 1.2' not in message
        finally:
            thread.join(6)
        assert not thread.is_alive()
        assert len(server_errors) == 1
        assert isinstance(server_errors[0], ssl.SSLError)
