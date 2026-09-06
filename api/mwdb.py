"""Fixed-origin MWDB retrieval inside a disposable resource-limited worker."""
import json
import os
from pathlib import Path
import re
import ssl
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, Request


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('MWDB redirects are disabled; configure the canonical API URL')


def scan_remote(payload, progress=lambda info: None):
    from yarax_editor import Compiler
    from yaraxgui.scanning.scanner import YaraScanner
    from .scan_manager import embed_match_snippets
    from .workers import scan_bytes
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    ca_file = os.environ.get('YARAXGUI_MWDB_CA_FILE')
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
    opener = build_opener(HTTPSHandler(context=context), NoRedirect())
    base = payload['url'].rstrip('/')
    maximum = int(os.environ.get('YARAXGUI_MAX_FILE_MB', '100')) * 1024**2
    def get(path, maximum):
        req = Request(base + path, headers={'Authorization': 'Bearer ' + payload['token']})
        try:
            with opener.open(req, timeout=15) as response:
                body = response.read(maximum + 1)
                if len(body) > maximum:
                    raise ValueError('MWDB response exceeds the configured size limit')
                return body
        except HTTPError as exc:
            raise ValueError(f'MWDB returned HTTP {exc.code}') from None
    validation = Compiler().validate(payload['text'])
    if not validation.valid:
        raise ValueError('\n'.join(d.message for d in validation.diagnostics if d.severity == 'error'))
    scanner = YaraScanner()
    hashes, seen = [], set()
    single = payload.get('file_hash')
    if single:
        hashes = [(single, single)]
    else:
        older = None
        while len(hashes) < payload['limit']:
            query = {'count': min(payload['batch_size'], payload['limit'] - len(hashes))}
            if payload.get('query'):
                query['query'] = payload['query']
            if older:
                query['older_than'] = older
            page = json.loads(get('/file?' + urlencode(query), 2 * 1024**2))
            page = page if isinstance(page, list) else page.get('files', [])
            if not page:
                break
            added = 0
            for item in page:
                sha = item.get('sha256', item.get('id', ''))
                if not re.fullmatch('[a-fA-F0-9]{64}', sha):
                    raise ValueError('MWDB returned an invalid file hash')
                if sha not in seen:
                    seen.add(sha)
                    hashes.append((sha, str(item.get('file_name', sha))[:200]))
                    added += 1
                if len(hashes) >= payload['limit']:
                    break
            if not added:
                break
            older = page[-1].get('sha256', page[-1].get('id'))
    hits, misses, errors = [], [], []
    size = 0
    for index, (sha, name) in enumerate(hashes):
        progress({'scanned': index, 'total': len(hashes), 'matches': len(hits), 'current_file': name})
        if not re.fullmatch('[a-fA-F0-9]{64}', sha):
            raise ValueError('Invalid file hash')
        try:
            data = get('/file/' + sha + '/download', maximum)
            result = scan_bytes(scanner, validation.rules, data, Path(sha))
            result['filename'] = name
            result['mwdb_sha256'] = sha
            hit = result.pop('hit')
            if hit:
                embed_match_snippets(result, data)
                hits.append(result)
            elif payload['include_misses']:
                misses.append(result)
            size += len(json.dumps(result))
            if size > 8 * 1024**2:
                raise OverflowError('Scan results exceed 8 MiB; reduce the scan limit')
        except OverflowError:
            raise
        except Exception as exc:
            errors.append(f'{sha}: {str(exc)[:512]}')
    return {'hits': hits, 'misses': misses, 'error_messages': errors,
            'stats': {'scanned': len(hashes), 'matches': len(hits), 'errors': len(errors)}}
