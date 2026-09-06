"""Qt-free, bounded binary analysis. Runs only in a disposable child process."""
import mmap
import re
import time

CHUNK_SIZE = 256 * 1024
MAX_RESULTS = 50_000
MAX_RESULT_BYTES = 16 * 1024 * 1024
PREVIEW_CHARS = 256


def compile_pattern(spec):
    pattern = spec.get('pattern', '')
    if not pattern:
        raise ValueError('Enter a search pattern first')
    if len(pattern) > 65536:
        raise ValueError('Search pattern exceeds 64 KiB')
    kind = spec['kind']
    flags = re.DOTALL
    if kind == 'hex':
        parts = []
        for token in pattern.split():
            if token in ('?', '??'):
                parts.append(b'.')
            elif len(token) == 2 and all(c in '0123456789abcdefABCDEF' for c in token):
                parts.append(re.escape(bytes([int(token, 16)])))
            else:
                raise ValueError(f'Invalid hex byte: {token}')
        if not parts:
            raise ValueError('Enter a hex pattern first')
        raw = b''.join(parts)
    elif kind == 'text':
        raw = re.escape(pattern.encode(spec.get('encoding', 'utf-8')))
        if not spec.get('case_sensitive', True):
            flags |= re.IGNORECASE
    elif kind == 'regex':
        raw = pattern.encode('latin-1')
    else:
        raise ValueError('Unknown search type')
    return re.compile(raw, flags)


def extract_strings(data, spec, cancelled, progress):
    """Keep only a preview and run length, even for a multi-gigabyte string.

    Both UTF-16 alignments are searched. Runs crossing chunks stay contiguous.
    UTF-16 extraction retains the existing printable ASCII + CR/LF alphabet.
    """
    minimum = max(2, min(256, int(spec.get('min_length', 4))))
    passes = []
    if spec.get('ascii', True):
        passes.append((1, 0, 'ASCII', re.compile(rb'[\x20-\x7e]+')))
    if spec.get('unicode', True):
        pattern = re.compile(rb'(?:[\x20-\x7e\r\n]\x00)+')
        passes.extend([(2, 0, 'UTF-16LE', pattern), (2, 1, 'UTF-16LE', pattern)])
    if not passes:
        raise ValueError('Select ASCII or UTF-16LE')
    size = len(data)
    for pass_index, (step, alignment, encoding, regex) in enumerate(passes):
        run_start, run_length, preview = 0, 0, b''
        for pos in range(alignment, size, CHUNK_SIZE):
            if cancelled():
                return
            end = min(pos + CHUNK_SIZE, size)
            if step == 2:
                end -= (end - pos) % 2
            chunk = data[pos:end]
            for match in regex.finditer(chunk):
                if step == 2 and match.start() % 2:
                    continue
                start, stop = pos + match.start(), pos + match.end()
                if run_length and start != run_start + run_length:
                    if run_length >= minimum * step:
                        yield (run_start, run_length, encoding,
                               preview.decode('ascii' if step == 1 else 'utf-16-le'))
                    run_length, preview = 0, b''
                if not run_length:
                    run_start = start
                room = PREVIEW_CHARS * step - len(preview)
                if room > 0:
                    preview += chunk[match.start():min(match.end(), match.start() + room)]
                run_length += stop - start
            if run_length and run_start + run_length < end:
                if run_length >= minimum * step:
                    yield (run_start, run_length, encoding,
                           preview.decode('ascii' if step == 1 else 'utf-16-le'))
                run_length, preview = 0, b''
            progress(int(100 * (pass_index + end / max(size, 1)) / len(passes)))
        if run_length >= minimum * step:
            yield (run_start, run_length, encoding,
                   preview.decode('ascii' if step == 1 else 'utf-16-le'))


def search_matches(data, spec, cancelled, progress):
    pattern = compile_pattern(spec)
    mode = spec.get('mode', 'all')
    requested_start = max(0, spec.get('start', 0))
    if mode == 'next' and requested_start > len(data):
        return
    start = min(requested_start, len(data))
    last = None
    # Search the entire mmap: anchors, lookbehind, and long matches must not
    # acquire false boundaries from arbitrary chunk/overlap windows.
    for match in pattern.finditer(data, start if mode == 'next' else 0):
        if cancelled():
            return
        offset, length = match.start(), match.end() - match.start()
        row = (offset, length, 'Bytes', data[offset:offset + min(length, 32)].hex(' '))
        if mode == 'previous':
            if offset >= start:
                break
            last = row
        else:
            yield row
            if mode == 'next':
                return
        progress(int(100 * match.end() / max(len(data), 1)))
    if last is not None:
        yield last


def worker_main(connection, snapshot, spec, stop):
    """Small pipe messages provide backpressure; never send one huge result list."""
    try:
        import os
        source = spec.get('_source_file')
        from .analysis_limits import limit_memory
        limit_memory(source[1][0] if source is not None else os.path.getsize(snapshot))
        if source is not None:
            path, expected = source
            connection.send(('phase', 'Preparing snapshot…'))
            with open(path, 'rb') as original, open(snapshot, 'wb') as target:
                stat = os.fstat(original.fileno())
                if (stat.st_size, stat.st_mtime_ns, stat.st_ino) != tuple(expected):
                    raise ValueError('Original file changed; reopen it before searching')
                while chunk := original.read(1024 * 1024):
                    if stop.is_set():
                        connection.send(('done', 'cancelled'))
                        return
                    target.write(chunk)
                stat = os.fstat(original.fileno())
                if (stat.st_size, stat.st_mtime_ns, stat.st_ino) != tuple(expected):
                    raise ValueError('Original file changed during snapshot')
        connection.send(('phase', 'Searching…'))
        with open(snapshot, 'rb') as stream:
            size = os.fstat(stream.fileno()).st_size
            data = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) if size else b''
            try:
                last_progress = [0.0]
                def progress(value):
                    now = time.monotonic()
                    if now - last_progress[0] >= .1:
                        connection.send(('progress', value))
                        last_progress[0] = now
                iterator = (extract_strings if spec['kind'] == 'strings' else search_matches)(
                    data, spec, stop.is_set, progress)
                batch, count, used = [], 0, 0
                reason = 'complete'
                for row in iterator:
                    if stop.is_set():
                        reason = 'cancelled'
                        break
                    cost = len(row[3].encode('utf-8')) + 256
                    if count >= MAX_RESULTS or used + cost > MAX_RESULT_BYTES:
                        reason = 'limit reached'
                        break
                    batch.append(row)
                    count += 1
                    used += cost
                    if len(batch) >= 256:
                        connection.send(('batch', batch))
                        batch = []
                if batch and not stop.is_set():
                    connection.send(('batch', batch))
                connection.send(('done', 'cancelled' if stop.is_set() else reason))
            finally:
                if size:
                    data.close()
    except Exception as exc:
        try:
            connection.send(('error', 'Search worker exceeded its memory budget; narrow the search' if isinstance(exc, MemoryError) else str(exc)))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        connection.close()
