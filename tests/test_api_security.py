"""Adversarial checks for the public API boundary, not a penetration-test claim."""
import asyncio
import base64
from dataclasses import replace
import json
import multiprocessing
import os
from pathlib import Path
import time
import zlib

import pytest
from fastapi.testclient import TestClient

from api.paths import FilePolicy
from api.security import APISecurityMiddleware, SecurityPolicy
from api.server import server_options
from api.workers import ProcessRunner, WorkerBusy, collect_files

KEY = 'test-only-security-key-0123456789abcdef'
PROD = {'YARAXGUI_API_KEY': KEY, 'YARAXGUI_ALLOWED_HOSTS': 'api.example.test'}
POLICY = SecurityPolicy.from_env(PROD)


@pytest.mark.parametrize('changes', [
    {'YARAXGUI_API_KEY': ''}, {'YARAXGUI_API_KEY': 'short'},
    {'YARAXGUI_API_KEY': 'change-me-to-a-long-random-string'},
    {'YARAXGUI_REQUIRE_HTTPS': '0'}, {'YARAXGUI_ALLOWED_HOSTS': ''},
    {'YARAXGUI_ALLOWED_HOSTS': '*'}, {'YARAXGUI_ALLOWED_HOSTS': '*.example.test'},
    {'YARAXGUI_ALLOWED_HOSTS': 'https://api.example.test'},
    {'YARAXGUI_CORS_ORIGINS': '*'}, {'YARAXGUI_CORS_ORIGINS': 'https://host/path'},
    {'YARAXGUI_MWDB_URL': 'http://127.0.0.1/admin'},
    {'YARAXGUI_MWDB_URL': 'https://user:password@host/api'},
    {'YARAXGUI_MAX_UPLOAD_MB': '-1'}, {'YARAXGUI_MAX_REQUESTS': '0'},
])
def test_public_config_rejects_unsafe_values(changes):
    with pytest.raises(ValueError):
        SecurityPolicy.from_env(PROD | changes)


@pytest.mark.parametrize('changes', [
    {}, {'YARAXGUI_TRUSTED_PROXIES': '*'}, {'YARAXGUI_TRUSTED_PROXIES': '0.0.0.0/0'},
    {'YARAXGUI_SSL_CERTFILE': 'cert.pem'},
    {'YARAXGUI_DEV_MODE': '1', 'YARAXGUI_HOST': '0.0.0.0'},
    {'YARAXGUI_DEV_MODE': '1', 'YARAXGUI_TRUSTED_PROXIES': '127.0.0.1'},
])
def test_launcher_rejects_unsafe_transport(changes):
    with pytest.raises(ValueError):
        server_options(PROD | changes)


def test_proxy_trust_is_explicit_and_development_binds_loopback():
    opts = server_options(PROD | {'YARAXGUI_TRUSTED_PROXIES': '172.30.77.2'})
    assert opts['proxy_headers'] and opts['forwarded_allow_ips'] == '172.30.77.2'
    assert opts['workers'] == 1
    opts = server_options({'YARAXGUI_DEV_MODE': '1'})
    assert opts['host'] == '127.0.0.1' and not opts['proxy_headers']


async def echo(scope, receive, send):
    await receive()
    await send({'type': 'http.response.start', 'status': 200, 'headers': []})
    await send({'type': 'http.response.body', 'body': b'{}'})


def request(middleware=None, *, headers=None, chunks=None, scheme='https', path='/rules/compile',
            client='198.51.100.1', method='POST', delay=0):
    middleware = middleware or APISecurityMiddleware(echo, POLICY)
    received, sent = [], []
    chunks = iter(chunks if chunks is not None else [{'type': 'http.request', 'body': b'{}'}])
    async def receive():
        received.append(True)
        if delay:
            await asyncio.sleep(delay)
        return next(chunks)
    async def send(message):
        sent.append(message)
    asyncio.run(middleware({'type': 'http', 'scheme': scheme, 'method': method,
        'path': path, 'client': (client, 1234),
        'headers': headers if headers is not None else [(b'host', b'api.example.test'), (b'x-api-key', KEY.encode())]}, receive, send))
    status = sent[0]['status'] if sent else None
    return status, received, sent


@pytest.mark.parametrize('headers,scheme,expected', [
    ([(b'host', b'api.example.test')], 'https', 403),
    ([(b'host', b'api.example.test'), (b'x-api-key', b'\xff')], 'https', 403),
    ([(b'host', b'api.example.test'), (b'x-api-key', KEY.encode()), (b'x-api-key', KEY.encode())], 'https', 403),
    ([(b'host', b'evil.example'), (b'x-api-key', KEY.encode())], 'https', 400),
    ([(b'host', b'api.example.test'), (b'host', b'evil')], 'https', 400),
    ([(b'host', b'api.example.test'), (b'x-api-key', KEY.encode()), (b'origin', b'https://evil')], 'https', 403),
    ([(b'host', b'api.example.test'), (b'x-api-key', KEY.encode()), (b'x-forwarded-proto', b'https')], 'http', 426),
])
def test_reject_before_reading_request_body(headers, scheme, expected):
    status, received, _ = request(headers=headers, scheme=scheme)
    assert status == expected and not received


def test_chunked_limit_and_length_smuggling():
    guard = APISecurityMiddleware(echo, replace(POLICY, max_json_bytes=3))
    status, _, _ = request(guard, chunks=[{'type': 'http.request', 'body': b'123', 'more_body': True},
                                         {'type': 'http.request', 'body': b'4'}])
    assert status == 413
    base = [(b'host', b'api.example.test'), (b'x-api-key', KEY.encode())]
    for extra, expected in [([(b'content-length', b'1')], 400),
                            ([(b'content-length', b'4')], 413),
                            ([(b'content-length', b'2'), (b'content-length', b'2')], 400),
                            ([(b'content-length', b'2'), (b'transfer-encoding', b'chunked')], 400)]:
        assert request(guard, headers=base + extra)[0] == expected


def test_slow_body_disconnect_and_capacity_release():
    guard = APISecurityMiddleware(echo, replace(POLICY, body_timeout=.01))
    assert request(guard, delay=.05)[0] == 408
    assert guard.active == 0
    assert request(guard, chunks=[{'type': 'http.disconnect'}])[0] is None
    assert guard.active == 0
    guard.active = POLICY.max_requests
    assert request(guard)[0] == 429
    # Health remains responsive even when every request slot is occupied.
    assert request(guard, path='/health', method='GET')[0] == 200


def test_rate_limits_cannot_be_reset_with_spoofed_forwarded_headers():
    guard = APISecurityMiddleware(echo, replace(POLICY, requests_per_minute=1))
    assert request(guard)[0] == 200
    assert request(guard, headers=[(b'host', b'api.example.test'), (b'x-api-key', KEY.encode()),
                                  (b'x-forwarded-for', b'203.0.113.99')])[0] == 429


def test_development_mode_rejects_network_clients_even_when_bound_manually():
    guard = APISecurityMiddleware(echo, SecurityPolicy(development=True, require_https=False))
    assert request(guard, scheme='http', headers=[(b'host', b'localhost')])[0] == 403
    assert request(guard, scheme='http', client='127.0.0.1', headers=[(b'host', b'localhost')])[0] == 200


def test_success_has_security_headers():
    status, _, messages = request()
    headers = dict(messages[0]['headers'])
    assert status == 200 and headers[b'cache-control'] == b'no-store'
    assert b'max-age=' in headers[b'strict-transport-security']


def test_path_prefix_symlinks_secrets_and_scan_enumeration(tmp_path):
    root = tmp_path / 'samples'
    root.mkdir()
    sibling = tmp_path / 'samples-secret'
    sibling.mkdir()
    secret = sibling / 'key'
    secret.write_text('secret')
    sample = root / 'sample'
    sample.write_bytes(b'ABC')
    database = root / 'rules.db'
    database.write_text('private')
    (root / 'rules.db-wal').write_text('private')
    (root / 'escape').symlink_to(secret)
    policy = FilePolicy([root], tmp_path / 'uploads', [database])
    for path in [secret, root / '../samples-secret/key', root / 'escape', database, root / 'rules.db-wal']:
        with pytest.raises(PermissionError):
            policy.validate(path)
    assert collect_files([root], True, [], policy) == [sample]
    with policy.open(sample) as stream:
        assert stream.read() == b'ABC'
    # No roots means uploads only, never unrestricted server access.
    with pytest.raises(PermissionError):
        FilePolicy([], tmp_path / 'uploads').validate(sample)


def test_symlink_swap_between_validation_and_open_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / 'samples'
    folder = root / 'folder'
    folder.mkdir(parents=True)
    sample = folder / 'file'
    sample.write_text('sample')
    other = tmp_path / 'secret'
    other.mkdir()
    (other / 'file').write_text('private')
    policy = FilePolicy([root], tmp_path / 'uploads')
    original = policy.validate
    def swap(path):
        resolved = original(path)
        sample.unlink()
        folder.rmdir()
        folder.symlink_to(other, target_is_directory=True)
        return resolved
    monkeypatch.setattr(policy, 'validate', swap)
    with pytest.raises((OSError, ValueError)):
        with policy.open(sample):
            pytest.fail('Opened swapped directory')


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    from api import yaraxgui_api as api
    from plugins import rule_repository
    from api.rule_repo import RuleRepository
    upload = tmp_path / 'uploads'
    upload.mkdir()
    monkeypatch.setenv('YARAXGUI_UPLOAD_DIR', str(upload))
    monkeypatch.setenv('YARAXGUI_ALLOWED_ROOTS', str(tmp_path / 'samples'))
    monkeypatch.setenv('YARAXGUI_REPO_DB', str(tmp_path / 'rules.db'))
    monkeypatch.setattr(api, 'UPLOAD_DIR', str(upload))
    monkeypatch.setattr(api, 'FILE_POLICY', FilePolicy([tmp_path / 'samples'], upload, [tmp_path / 'rules.db']))
    monkeypatch.setattr(rule_repository, '_repo', RuleRepository(str(tmp_path / 'rules.db')))
    with TestClient(api.app, client=('127.0.0.1', 50000), base_url='http://localhost') as client:
        yield client, api, upload


def test_upload_names_quota_cleanup_and_file_hashes(api_client, monkeypatch):
    client, api, upload = api_client
    monkeypatch.setattr(api, 'POLICY', replace(api.POLICY, upload_quota_bytes=4))
    result = client.post('/upload', files={'file': ('../../CON:stream', b'ABC')})
    assert result.status_code == 200
    body = result.json()
    assert body['filename'] == 'sample_CON_stream'
    info = client.post('/file/info', json={'path': body['path']})
    import hashlib
    assert info.json()['sha256'] == hashlib.sha256(b'ABC').hexdigest()
    result = client.post('/upload', files={'file': ('second', b'XX')})
    assert result.status_code == 413
    assert len(list(upload.iterdir())) == 1  # No partial upload after failure.
    assert client.delete('/upload/' + body['upload_id']).status_code == 200
    assert list(upload.iterdir()) == []


def test_health_minimal_and_api_input_limits(api_client):
    client, _, _ = api_client
    assert client.get('/health').json() == {'status': 'ok'}
    assert client.post('/rules/compile', json={'rule_text': '\u00e9' * (600 * 1024)}).status_code == 413
    assert client.post('/patterns/generate', json={'data_base64': '!!!!'}).status_code == 400
    assert client.post('/patterns/generate', json={'data_base64': 'A' * 90000}).status_code == 422
    assert client.get('/repo/rules?limit=-1').status_code == 422
    assert client.get('/repo/rules?limit=100000').status_code == 422
    assert client.get('/repo/rules?offset=-1').status_code == 422
    assert client.post('/repo/rules', json={'name':'x','rule_text':'a'*1048577}).status_code == 422
    assert client.post('/file/read', json={'path':'/etc/passwd'}).status_code == 403


def test_remote_mwdb_destination_is_not_request_controlled(api_client):
    client, _, _ = api_client
    result = client.post('/scan/mwdb', json={'rule_text':'rule x {condition:true}',
                         'mwdb_url':'http://169.254.169.254/latest/meta-data', 'mwdb_token':'secret'})
    assert result.status_code == 403
    result = client.post('/scan/mwdb', json={'rule_text':'rule x {condition:true}',
                         'mwdb_url':'https://trusted/api','mwdb_token':'secret','file_hash':'../../secret'})
    assert result.status_code == 422


def test_worker_transform_output_bomb_timeout_and_cancellation():
    runner = ProcessRunner(capacity=1)
    result = runner.run('transform', {'data_base64':'QUJD', 'steps':[{'name':'Base64 encode','params':{}}]})
    assert base64.b64decode(result['data_base64']) == b'QUJD'
    compressed = zlib.compress(b'A' * (9 * 1024**2))
    with pytest.raises(ValueError, match='output exceeds'):
        runner.run('transform', {'data_base64':base64.b64encode(compressed).decode(),
                                'steps':[{'name':'Zlib decompress','params':{}}]})
    before = {p.pid for p in multiprocessing.active_children()}
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        runner.run('compile', {'text':'rule x {condition:true}'}, timeout=.001)
    with pytest.raises(InterruptedError):
        runner.run('compile', {'text':'rule x {condition:true}'}, cancelled=lambda: True)
    assert time.monotonic() - start < 5
    assert {p.pid for p in multiprocessing.active_children()} == before
    # Capacity is returned after both aborted workers.
    assert runner.run('compile', {'text':'rule x {condition:true}'})['success']


def test_scan_worker_progress_and_results(api_client):
    client, api, upload = api_client
    sample = upload / 'sample'
    sample.write_bytes(b'MZABC')
    progress = []
    result = api._runner.run('scan', {'text':'rule x {strings:$a="ABC" condition:$a}',
        'paths':[str(sample)], 'recursive':False,'exclusions':[]}, progress=progress.append)
    assert progress and progress[0]['total'] == 1
    assert result['stats']['matches'] == 1
    assert result['hits'][0]['matched_rules'][0]['identifier'] == 'x'


def test_scan_jobs_capacity_cancel_and_secret_cleanup():
    from api.jobs import SecureScanManager
    policy = replace(POLICY, mwdb_url='https://mwdb.example/api')
    manager = SecureScanManager(policy)
    job = manager.create_mwdb_job('rule x {condition:true}', policy.mwdb_url, 'secret')
    manager.create_job('rule x {condition:true}', [])
    with pytest.raises(WorkerBusy):
        manager.create_job('rule x {condition:true}', [])
    job.cancel()
    asyncio.run(manager.run_job(job))
    assert job.status == 'cancelled' and job.completed_at and not job.mwdb_token


def test_only_trusted_proxy_can_assert_https():
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
    guard = ProxyHeadersMiddleware(APISecurityMiddleware(echo, POLICY), trusted_hosts='172.30.77.2')
    headers = [(b'host', b'api.example.test'), (b'x-api-key', KEY.encode()),
               (b'x-forwarded-proto', b'https'), (b'x-forwarded-for', b'198.51.100.20')]
    assert request(guard, headers=headers, scheme='http', client='172.30.77.2')[0] == 200
    assert request(guard, headers=headers, scheme='http', client='198.51.100.20')[0] == 426


def test_same_origin_browser_and_explicit_cross_origin_preflight():
    from starlette.middleware.cors import CORSMiddleware
    inner = CORSMiddleware(echo, allow_origins=['https://ui.example.test'],
                          allow_methods=['POST'], allow_headers=['X-API-Key'])
    guard = APISecurityMiddleware(inner, replace(POLICY, cors_origins=('https://ui.example.test',)))
    headers = [(b'host', b'api.example.test'), (b'x-api-key', KEY.encode()),
               (b'origin', b'https://api.example.test')]
    assert request(guard, headers=headers)[0] == 200
    status, _, messages = request(guard, method='OPTIONS', headers=[(b'host', b'api.example.test'),
        (b'origin', b'https://ui.example.test'), (b'access-control-request-method', b'POST'),
        (b'access-control-request-headers', b'x-api-key')])
    assert status == 200
    assert dict(messages[0]['headers'])[b'access-control-allow-origin'] == b'https://ui.example.test'


def test_protected_hardlinks_are_not_readable(tmp_path):
    root = tmp_path / 'samples'
    root.mkdir()
    secret = tmp_path / 'rules.db'
    secret.write_text('private')
    link = root / 'innocent'
    os.link(secret, link)
    policy = FilePolicy([root], tmp_path / 'uploads', [secret])
    with pytest.raises(PermissionError):
        with policy.open(link):
            pytest.fail('Read a protected database through a hard link')


def partial_reply_worker(connection, operation, payload):
    import struct
    os.write(connection.fileno(), struct.pack('!i', 1024) + b'x')
    payload['ready'].set()
    time.sleep(15)


def test_partial_worker_message_cannot_defeat_timeout(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    monkeypatch.setattr('api.workers.worker_main', partial_reply_worker)
    runner = ProcessRunner()
    ready = runner.context.Event()
    with ThreadPoolExecutor(1) as pool:
        pending = pool.submit(runner.run, 'unused', {'ready':ready}, timeout=3)
        assert ready.wait(2)
        with pytest.raises(TimeoutError):
            pending.result(timeout=5)


def test_body_deadline_applies_even_when_chunks_are_already_buffered():
    guard = APISecurityMiddleware(echo, replace(POLICY, body_timeout=0))
    assert request(guard)[0] == 408


def test_malformed_unicode_and_validation_errors_never_echo_credentials(api_client):
    client, _, _ = api_client
    for path, body in [('/rules/validate', b'{"rule_text":"\\ud800"}'),
                       ('/repo/rules', b'{"name":"x","rule_text":"\\ud800"}')]:
        assert client.post(path, content=body, headers={'content-type':'application/json'}).status_code in (400, 422)
    response = client.post('/scan/mwdb', json={'mwdb_token':'private-test-token'})
    assert response.status_code == 422
    assert 'private-test-token' not in response.text


@pytest.mark.parametrize('host', ['0.0.0.0', '::', '0:0:0:0:0:0:0:0'])
def test_unspecified_site_address_is_rejected(host):
    with pytest.raises(ValueError, match='YARAXGUI_DOMAIN.*listen addresses'):
        SecurityPolicy.from_env(PROD | {'YARAXGUI_ALLOWED_HOSTS': host + ',127.0.0.1'})


@pytest.mark.parametrize('host', ['api.example.test', '192.168.1.50', '2001:db8::50'])
def test_site_address_is_independent_of_listener_bind(host):
    opts = server_options(PROD | {
        'YARAXGUI_ALLOWED_HOSTS': host,
        'YARAXGUI_HOST': '0.0.0.0',
        'YARAXGUI_TRUSTED_PROXIES': '172.30.77.2',
    })
    assert opts['host'] == '0.0.0.0'
