"""Real Caddy IP TLS through a different destination address (Docker/NAT).

Run with CADDY_BINARY=/path/to/caddy python -m pytest tests/test_caddy_ip_tls.py.
Certificates and storage are temporary; no system trust store is modified.
"""
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from yaraxgui.network import api_urlopen


@pytest.fixture
def caddy_binary():
    binary = os.environ.get('CADDY_BINARY') or shutil.which('caddy')
    if not binary:
        pytest.skip('Caddy executable required; set CADDY_BINARY')
    return binary


def adapted_config(binary, host):
    result = subprocess.run(
        [binary, 'adapt', '--config', str(Path(__file__).resolve().parents[1] / 'deployment/Caddyfile'),
         '--adapter', 'caddyfile'],
        env=os.environ | {'YARAXGUI_DOMAIN': host}, check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def test_public_hostname_keeps_automatic_certificate_issuance(caddy_binary):
    config = adapted_config(caddy_binary, 'yara.example.com')
    server = config['apps']['http']['servers']['srv0']
    assert server['tls_connection_policies'] == [{'default_sni': 'yara.example.com'}]
    assert server['routes'][0]['match'] == [{'host': ['yara.example.com']}]
    assert 'tls' not in config['apps']  # No forced private CA for public domains.


def test_ip_tls_with_nat_trust_and_authentication(caddy_binary, tmp_path, monkeypatch):
    seen = []

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get('X-API-Key'), self.headers.get('Host')))
            self.send_response(200 if self.headers.get('X-API-Key') == 'test-only-key' else 403)
            self.end_headers()
            self.wfile.write(b'{"total_rules":1}')

        def log_message(self, *args):
            pass

    upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    config = adapted_config(caddy_binary, '192.168.1.50')
    server = config['apps']['http']['servers']['srv0']
    server['listen'] = [f'127.0.0.1:{port}']
    server['automatic_https'] = {'disable_redirects': True}
    route = server['routes'][0]['handle'][0]['routes'][0]['handle'][-1]
    route['upstreams'] = [{'dial': f'127.0.0.1:{upstream.server_port}'}]
    config['storage'] = {'module': 'file_system', 'root': str(tmp_path / 'storage')}
    config['apps']['pki'] = {'certificate_authorities': {'local': {'install_trust': False}}}
    config['admin']['config'] = {'persist': False}
    config_path = tmp_path / 'caddy.json'
    config_path.write_text(json.dumps(config))
    cert = tmp_path / 'storage/pki/authorities/local/root.crt'
    # Route client TCP connections to loopback while preserving the URL's IP,
    # Host and certificate verification. Caddy sees a different destination IP.
    connect = socket.create_connection
    monkeypatch.setattr(socket, 'create_connection',
        lambda address, *args, **kwargs: connect(('127.0.0.1', port), *args, **kwargs))
    monkeypatch.setenv('no_proxy', '*')
    monkeypatch.setenv('NO_PROXY', '*')
    url = f'https://192.168.1.50:{port}/repo/stats'
    process = None
    try:
        with (tmp_path / 'caddy.log').open('w+') as log:
            process = subprocess.Popen([caddy_binary, 'run', '--config', str(config_path)],
                                       stdout=log, stderr=log)
            deadline = time.monotonic() + 10
            while True:
                try:
                    with api_urlopen(Request(url, headers={'X-API-Key': 'test-only-key'}),
                                     {'api_ca_file': str(cert)}.get, timeout=1) as response:
                        assert json.load(response) == {'total_rules': 1}
                    break
                except (URLError, OSError):
                    if time.monotonic() >= deadline or process.poll() is not None:
                        log.seek(0)
                        pytest.fail(log.read())
                    time.sleep(0.1)
            with pytest.raises(HTTPError) as denied:
                api_urlopen(url, {'api_ca_file': str(cert)}.get)
            assert denied.value.code == 403
            denied.value.close()
            for target, settings in [(url, None),
                                     (url.replace('192.168.1.50', '192.168.1.51'),
                                      {'api_ca_file': str(cert)}.get)]:
                with pytest.raises(URLError) as failure:
                    api_urlopen(target, settings)
                assert isinstance(failure.value.reason, ssl.SSLCertVerificationError)
            assert seen == [('/repo/stats', 'test-only-key', f'192.168.1.50:{port}'),
                            ('/repo/stats', None, f'192.168.1.50:{port}')]
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        thread.join(2)
