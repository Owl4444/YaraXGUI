"""Fail-closed API policy and guards that run before request body parsing."""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
import hmac
import ipaddress
import json
import os
import tempfile
import time
from urllib.parse import urlsplit


def flag(env, name, default=False):
    value = env.get(name, str(int(default))).lower()
    if value not in {'0', '1', 'false', 'true'}:
        raise ValueError(f'{name} must be 0 or 1')
    return value in {'1', 'true'}


def number(env, name, default, minimum=1, maximum=1000000):
    value = int(env.get(name, default))
    if not minimum <= value <= maximum:
        raise ValueError(f'{name} must be between {minimum} and {maximum}')
    return value


@dataclass(frozen=True)
class SecurityPolicy:
    api_key: str = ''
    development: bool = False
    require_https: bool = True
    cors_origins: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()
    expose_docs: bool = False
    requests_per_minute: int = 120
    max_requests: int = 8
    max_json_bytes: int = 4 * 1024 * 1024
    max_upload_bytes: int = 100 * 1024 * 1024
    upload_quota_bytes: int = 1024 * 1024 * 1024
    body_timeout: int = 60
    mwdb_url: str = ''

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        dev = flag(env, 'YARAXGUI_DEV_MODE')
        split = lambda name: tuple(v.strip() for v in env.get(name, '').split(',') if v.strip())
        policy = cls(
            api_key=env.get('YARAXGUI_API_KEY', ''), development=dev,
            require_https=flag(env, 'YARAXGUI_REQUIRE_HTTPS', not dev),
            cors_origins=split('YARAXGUI_CORS_ORIGINS'), allowed_hosts=split('YARAXGUI_ALLOWED_HOSTS'),
            expose_docs=flag(env, 'YARAXGUI_ENABLE_DOCS', dev),
            requests_per_minute=number(env, 'YARAXGUI_RATE_LIMIT', 120),
            max_requests=number(env, 'YARAXGUI_MAX_REQUESTS', 8, maximum=64),
            max_upload_bytes=number(env, 'YARAXGUI_MAX_UPLOAD_MB', 100, maximum=1024) * 1024**2,
            upload_quota_bytes=number(env, 'YARAXGUI_UPLOAD_QUOTA_MB', 1024, maximum=102400) * 1024**2,
            body_timeout=number(env, 'YARAXGUI_BODY_TIMEOUT', 60, maximum=600),
            mwdb_url=env.get('YARAXGUI_MWDB_URL', '').rstrip('/'),
        )
        if policy.api_key and (len(policy.api_key) > 256 or any(not 33 <= ord(c) <= 126 for c in policy.api_key)):
            raise ValueError('API keys must contain 32–256 visible ASCII characters without spaces')
        if not dev:
            if len(policy.api_key.encode('utf-8')) < 32 or policy.api_key.startswith('change-me'):
                raise ValueError('Set a random YARAXGUI_API_KEY of at least 32 bytes; anonymous access requires explicit loopback development mode')
            if not policy.require_https:
                raise ValueError('Public API mode requires HTTPS')
            if not policy.allowed_hosts or '*' in policy.allowed_hosts:
                raise ValueError('Set YARAXGUI_ALLOWED_HOSTS to the public API hostname (without scheme or port)')
        for host in policy.allowed_hosts:
            if any(c in host for c in '/@?#* \t\r\n') or not host or host != host.lower():
                raise ValueError('Allowed hosts must be lowercase hostnames or IP addresses, without ports or wildcards')
            if ':' in host:
                ipaddress.IPv6Address(host)
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None and address.is_unspecified:
                raise ValueError('YARAXGUI_ALLOWED_HOSTS (YARAXGUI_DOMAIN in Compose) must use the server hostname or reachable IP; 0.0.0.0 and :: are listen addresses, not site addresses')
        for origin in policy.cors_origins:
            parsed = urlsplit(origin)
            parsed.port
            if origin == '*' or parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
                raise ValueError('CORS origins must be explicit HTTP(S) origins, not wildcards')
        if policy.mwdb_url:
            parsed = urlsplit(policy.mwdb_url)
            parsed.port
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError('YARAXGUI_MWDB_URL must be a trusted, fixed HTTPS API URL without credentials, query, or fragment')
        return policy


class RateLimiter:
    """Bounded token buckets; forwarded headers are never parsed here."""
    def __init__(self, rate, max_clients=4096):
        self.rate, self.max_clients = rate, max_clients
        self.clients = OrderedDict()

    def allow(self, client):
        now = time.monotonic()
        tokens, previous = self.clients.pop(client, (float(self.rate), now))
        tokens = min(self.rate, tokens + (now - previous) * self.rate / 60)
        accepted = tokens >= 1
        self.clients[client] = (tokens - 1 if accepted else tokens, now)
        while len(self.clients) > self.max_clients:
            self.clients.popitem(last=False)
        return accepted


class APISecurityMiddleware:
    def __init__(self, app, policy):
        self.app, self.policy = app, policy
        self.limiter = RateLimiter(policy.requests_per_minute)
        self.active = 0

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        policy = self.policy
        headers = {}
        for key, value in scope.get('headers', []):
            headers.setdefault(key.lower(), []).append(value)
        origin = headers.get(b'origin', [b''])[0].decode('latin-1')
        secure = scope.get('scheme') == 'https'
        response_started = False

        async def secure_send(message):
            nonlocal response_started
            if message['type'] == 'http.response.start':
                response_started = True
                extras = [(b'x-content-type-options', b'nosniff'), (b'cache-control', b'no-store'),
                          (b'x-frame-options', b'DENY'), (b'referrer-policy', b'no-referrer')]
                if secure:
                    extras.append((b'strict-transport-security', b'max-age=31536000'))
                message = dict(message, headers=list(message.get('headers', [])) + extras)
            await send(message)

        async def reject(status, detail):
            body = json.dumps({'detail': detail}).encode('utf-8')
            response_headers = [(b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())]
            if status == 429:
                response_headers.append((b'retry-after', b'5'))
            await secure_send({'type': 'http.response.start', 'status': status, 'headers': response_headers})
            await send({'type': 'http.response.body', 'body': body})

        host_values = headers.get(b'host', [])
        if len(host_values) != 1 or len(headers.get(b'origin', [])) > 1:
            return await reject(400, 'Invalid request headers')
        try:
            authority = urlsplit('//' + host_values[0].decode('ascii'))
            authority.port
            host = authority.hostname
            if authority.username or authority.password or authority.path or authority.query or authority.fragment:
                host = None
        except (ValueError, UnicodeError):
            host = None
        if not host or (policy.allowed_hosts and host not in policy.allowed_hosts):
            return await reject(400, 'Invalid host')
        if policy.development and not policy.allowed_hosts and host not in ('localhost', '127.0.0.1', '::1'):
            return await reject(400, 'Development mode requires a localhost Host header')
        same_origin = origin == scope.get('scheme', 'http') + '://' + host_values[0].decode('ascii').lower()
        client = (scope.get('client') or ('unknown', 0))[0]
        if policy.development:
            try:
                loopback = ipaddress.ip_address(client).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                return await reject(403, 'Development mode only accepts loopback clients')
        if not self.limiter.allow(client):
            return await reject(429, 'Request rate limit exceeded')
        health = scope['path'] == '/health' and scope['method'] == 'GET'
        if not health:
            if policy.require_https and not secure:
                return await reject(426, 'HTTPS is required; configure TLS or a trusted HTTPS reverse proxy')
            if origin and not same_origin and origin not in policy.cors_origins:
                return await reject(403, 'Origin is not allowed')
            preflight = scope['method'] == 'OPTIONS' and origin and b'access-control-request-method' in headers
            if not preflight:
                keys = headers.get(b'x-api-key', [])
                if policy.api_key and (len(keys) != 1 or not hmac.compare_digest(keys[0], policy.api_key.encode('utf-8'))):
                    return await reject(403, 'Invalid API key')
                if not policy.api_key and not policy.development:
                    return await reject(503, 'Authentication is not configured')
        if health:
            return await self.app(scope, receive, secure_send)
        if self.active >= policy.max_requests:
            return await reject(429, 'Server request capacity reached')
        lengths = headers.get(b'content-length', [])
        if len(lengths) > 1 or (lengths and b'transfer-encoding' in headers):
            return await reject(400, 'Ambiguous request length')
        limit = policy.max_upload_bytes + 65536 if scope['path'] == '/upload' else policy.max_json_bytes
        try:
            declared = int(lengths[0]) if lengths else None
            if declared is not None and (declared < 0 or declared > limit):
                return await reject(413, 'Request body too large')
        except ValueError:
            return await reject(400, 'Invalid request length')
        self.active += 1
        try:
            # Authenticate before buffering or multipart parsing. Spooling keeps
            # memory bounded; this enforces chunked bodies and dishonest lengths too.
            with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as spool:
                used, deadline = 0, time.monotonic() + policy.body_timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return await reject(408, 'Request body timed out')
                    try:
                        message = await asyncio.wait_for(receive(), remaining)
                    except TimeoutError:
                        return await reject(408, 'Request body timed out')
                    if message['type'] == 'http.disconnect':
                        return
                    body = message.get('body', b'')
                    used += len(body)
                    if used > limit:
                        return await reject(413, 'Request body too large')
                    spool.write(body)
                    if not message.get('more_body'):
                        break
                if declared is not None and declared != used:
                    return await reject(400, 'Request length mismatch')
                spool.seek(0)
                delivered = False
                async def replay():
                    nonlocal delivered
                    if delivered:
                        return await receive()
                    body = spool.read(65536)
                    more = spool.tell() < used
                    delivered = not more
                    return {'type': 'http.request', 'body': body, 'more_body': more}
                await self.app(scope, replay, secure_send)
        except OSError:
            if response_started:
                raise
            return await reject(503, 'Temporary request storage is unavailable')
        finally:
            self.active -= 1
