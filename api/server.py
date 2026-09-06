"""Validated single-process API launcher for direct TLS or a trusted proxy."""
import argparse
import ipaddress
import os
import ssl

from api.security import SecurityPolicy, number


def server_options(env=None, *, host=None, port=None):
    env = os.environ if env is None else env
    policy = SecurityPolicy.from_env(env)
    host = host or env.get('YARAXGUI_HOST', '127.0.0.1' if policy.development else '0.0.0.0')
    port = port or number(env, 'YARAXGUI_PORT', 7777, maximum=65535)
    cert, key = env.get('YARAXGUI_SSL_CERTFILE'), env.get('YARAXGUI_SSL_KEYFILE')
    trusted = env.get('YARAXGUI_TRUSTED_PROXIES', '')
    if bool(cert) != bool(key):
        raise ValueError('Set both YARAXGUI_SSL_CERTFILE and YARAXGUI_SSL_KEYFILE')
    if cert and trusted:
        raise ValueError('Choose direct TLS or trusted proxy mode, not both')
    if policy.development:
        if not ipaddress.ip_address(host).is_loopback or trusted:
            raise ValueError('Development mode must bind to a loopback IP without proxy headers')
    elif not cert and not trusted:
        raise ValueError('Public API requires TLS certificate/key files or explicit YARAXGUI_TRUSTED_PROXIES')
    for value in trusted.split(',') if trusted else ():
        network = ipaddress.ip_network(value.strip(), strict=False)
        if network.prefixlen == 0:
            raise ValueError('Never trust all proxy addresses; specify only your proxy IP or dedicated subnet')
    number(env, 'YARAXGUI_MAX_FILE_MB', 100, maximum=1024)
    number(env, 'YARAXGUI_MAX_SCAN_FILES', 1000, maximum=10000)
    number(env, 'YARAXGUI_SCAN_TIMEOUT', 60, maximum=600)
    return dict(host=host, port=port, ssl_certfile=cert, ssl_keyfile=key,
                ssl_ciphers=None,  # Keep Python's secure defaults, not Uvicorn's legacy TLSv1 cipher list.
                proxy_headers=bool(trusted), forwarded_allow_ips=trusted,
                workers=1, limit_concurrency=32, backlog=64,
                http="h11", h11_max_incomplete_event_size=16384,
                timeout_keep_alive=5, timeout_graceful_shutdown=10,
                server_header=False, access_log=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host')
    parser.add_argument('--port', type=int, choices=range(1, 65536), metavar='PORT')
    args = parser.parse_args()
    try:
        options = server_options(host=args.host, port=args.port)
    except ValueError as exc:
        parser.error(str(exc))
    import uvicorn
    config = uvicorn.Config('api.yaraxgui_api:app', **options)
    config.load()
    if config.ssl:
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    uvicorn.Server(config).run()


if __name__ == '__main__':
    main()
