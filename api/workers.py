"""Disposable, memory/time bounded workers for remotely supplied input.

This limits resource consumption, not native-code exploitation. The deployment
container and its filesystem/network policy remain the security boundary.
"""
import base64
import json
import multiprocessing
import os
import queue
import threading
import time

MAX_OUTPUT_BYTES = 16 * 1024 * 1024


class WorkerBusy(RuntimeError):
    pass


def worker_main(connection, operation, payload):
    try:
        from hex_editor.analysis_limits import limit_memory
        limit_memory(0)
        result = execute(operation, payload, progress=lambda info: connection.send_bytes(json.dumps({'progress': info}).encode()))
        encoded = json.dumps({'result': result}, ensure_ascii=False).encode('utf-8')
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise ValueError('Result exceeds the 16 MiB response limit')
        connection.send_bytes(encoded)
    except Exception as exc:
        detail = '\n'.join([str(exc)] + [d.message for d in getattr(exc, 'diagnostics', ())])
        connection.send_bytes(json.dumps({'error': detail[:4096]}).encode('utf-8'))
    finally:
        connection.close()


def execute(operation, payload, progress=lambda info: None):
    from yarax_editor import Compiler, CompileOptions
    options = CompileOptions(allow_includes=payload.get('allow_includes', False))
    if operation == 'repo_split':
        from api.rule_repo import RuleRepository
        rows = RuleRepository._split_rules(payload['text'])
        if len(rows) > 1000:
            raise ValueError('Import at most 1000 rules per request')
        return rows
    if operation == 'compile':
        result = Compiler(options).validate(payload['text'])
        return {'success': result.valid, 'rules_count': len(list(result.rules)) if result.valid else 0,
                'message': 'Compilation successful' if result.valid else '',
                'error': '\n'.join(d.message for d in result.diagnostics if d.severity == 'error')}
    if operation == 'validate':
        from yaraxgui.editor.services import validate_source
        return validate_source(payload['text'], compile_options=options)
    if operation == 'format':
        if len(payload['text'].encode('utf-8')) > 256 * 1024:
            raise ValueError('Formatting exceeds the 256 KiB limit')
        from yarax_editor import format_source
        return format_source(payload['text'], compiler=Compiler(options))
    if operation == 'transform':
        from hex_editor.transforms import load_builtin_plugins, RecipeStep, apply_recipe, debug_log_clear, debug_log_get
        load_builtin_plugins()
        debug_log_clear()
        data = base64.b64decode(payload['data_base64'], validate=True)
        for step in payload['steps']:
            data = apply_recipe(data, [RecipeStep(spec_name=step['name'], params=step['params'])])
            if len(data) > 8 * 1024 * 1024:
                raise ValueError('Transform output exceeds 8 MiB')
        return {'success': True, 'data_base64': base64.b64encode(data).decode('ascii'),
                'output_size': len(data), 'debug_log': [line[:2048] for line in debug_log_get()[:100]]}
    if operation == 'scan':
        from api.paths import configured_file_policy
        from yaraxgui.scanning.scanner import YaraScanner
        from api.scan_manager import embed_match_snippets, is_excluded
        validation = Compiler(options).validate(payload['text'])
        if not validation.valid:
            raise ValueError('\n'.join(d.message for d in validation.diagnostics if d.severity == 'error'))
        policy = configured_file_policy()
        hits, misses, errors = [], [], []
        scanner = YaraScanner()
        # The whole job runs under the parent's timeout; every file is checked
        # again in the worker immediately before opening it.
        files = collect_files(payload['paths'], payload['recursive'], payload['exclusions'], policy)
        used = 0
        for index, path in enumerate(files):
            progress({'scanned': index, 'total': len(files), 'matches': len(hits), 'current_file': path.name})
            try:
                with policy.open(path) as stream:
                    maximum = int(os.environ.get('YARAXGUI_MAX_FILE_MB', '100')) * 1024**2
                    if os.fstat(stream.fileno()).st_size > maximum:
                        raise ValueError('File exceeds configured scan size limit')
                    data = stream.read(maximum + 1)
                    if len(data) > maximum:
                        raise ValueError('File exceeds configured scan size limit')
                result = scan_bytes(scanner, validation.rules, data, path)
                hit = result.pop('hit')
                embed_match_snippets(result, data)
                used += len(json.dumps(result))
                if used > 8 * 1024 * 1024:
                    raise OverflowError('Scan results exceed 8 MiB; scan fewer files')
                (hits if hit else misses).append(result)
            except OverflowError:
                raise
            except Exception as exc:
                errors.append(f'{path.name}: {str(exc)[:512]}')
        return {'hits': hits, 'misses': misses, 'error_messages': errors,
                'stats': {'scanned': len(files), 'matches': len(hits), 'errors': len(errors)}}
    if operation == 'mwdb':
        from api.mwdb import scan_remote
        return scan_remote(payload, progress)
    raise ValueError('Unknown worker operation')


def scan_bytes(scanner, rules, data, path):
    import hashlib
    results = rules.scan(data)
    matched = scanner._extract_match_details(results.matching_rules)
    return {'hit': bool(matched), 'filename': path.name, 'filepath': str(path),
            'file_size': len(data), 'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(), 'sha256': hashlib.sha256(data).hexdigest(),
            'matched_rules': matched}


def collect_files(paths, recursive, exclusions, policy):
    from api.scan_manager import embed_match_snippets, is_excluded
    files, seen = [], set()
    maximum = int(os.environ.get('YARAXGUI_MAX_SCAN_FILES', '1000'))
    def add(path):
        if path.is_symlink() or is_excluded(path, exclusions):
            return
        try:
            resolved = policy.validate(path)
        except PermissionError:
            return
        if resolved.is_file() and resolved not in seen:
            if len(files) >= maximum:
                raise ValueError('Too many files; narrow the scan scope')
            seen.add(resolved)
            files.append(resolved)
    for raw in paths:
        root = policy.validate(raw)
        if root.is_dir():
            for directory, dirs, names in os.walk(root, followlinks=False):
                from pathlib import Path
                folder = Path(directory)
                dirs[:] = [d for d in dirs if not (folder / d).is_symlink()
                           and not is_excluded(folder / d, exclusions)]
                for name in names:
                    add(folder / name)
                if not recursive:
                    break
        else:
            add(root)
    return files


class ProcessRunner:
    def __init__(self, capacity=2, timeout=30):
        self.slots = threading.BoundedSemaphore(capacity)
        self.timeout = timeout
        self.context = multiprocessing.get_context('spawn')

    def run(self, operation, payload, *, cancelled=None, timeout=None, progress=lambda info: None):
        if not self.slots.acquire(blocking=False):
            raise WorkerBusy('Server worker capacity reached; retry later')
        receiver = sender = process = reader = None
        stopped = threading.Event()
        messages = queue.Queue(maxsize=1)
        try:
            receiver, sender = self.context.Pipe(duplex=False)
            process = self.context.Process(target=worker_main, args=(sender, operation, payload), daemon=True)
            process.start()
            sender.close()

            def read_messages():
                while not stopped.is_set():
                    try:
                        reply = json.loads(receiver.recv_bytes(MAX_OUTPUT_BYTES))
                    except (EOFError, OSError, ValueError):
                        reply = {'worker_stopped': True}
                    while not stopped.is_set():
                        try:
                            messages.put(reply, timeout=.05)
                            break
                        except queue.Full:
                            pass
                    if 'worker_stopped' in reply or 'progress' not in reply:
                        break

            # A pipe may contain only a partial framed message. Reading on a
            # separate thread keeps deadlines/cancellation effective even then.
            reader = threading.Thread(target=read_messages, daemon=True)
            reader.start()
            deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
            while True:
                if cancelled and cancelled():
                    raise InterruptedError('Scan cancelled')
                if time.monotonic() > deadline:
                    raise TimeoutError('Operation exceeded its time limit')
                try:
                    reply = messages.get(timeout=.05)
                except queue.Empty:
                    continue
                if 'worker_stopped' in reply:
                    raise RuntimeError('Worker stopped or exceeded its memory/output limit')
                if 'progress' in reply:
                    progress(reply['progress'])
                    continue
                if 'error' in reply:
                    raise ValueError(reply['error'])
                return reply['result']
        finally:
            stopped.set()
            if sender is not None:
                sender.close()
            if process is not None and process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join(timeout=1)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=1)
                process.close()
            if reader is not None:
                reader.join(timeout=1)
            if receiver is not None:
                receiver.close()
            self.slots.release()
