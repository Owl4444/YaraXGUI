"""Atomic YARA drafts and append-only hex journals, outside the checkout.

Recovery workers never access Qt widgets. A session lock prevents recovering
another running instance's work. Originals are never overwritten by recovery.
"""
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QLockFile
from yaraxgui.repository.local_store import local_database_path

_SESSIONS = {}
_CLAIMS = {}
IO_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix='recovery')
COPY_CHUNK = 1024 * 1024


def recovery_root():
    return Path(os.environ.get('YARAXGUI_RECOVERY_DIR') or local_database_path().parent / 'recovery')


def session_dir():
    root = recovery_root()
    key = str(root)
    if key not in _SESSIONS:
        folder = root / uuid.uuid4().hex
        folder.mkdir(parents=True, mode=0o700)
        lock = QLockFile(str(folder / 'session.lock'))
        lock.setStaleLockTime(0)
        if not lock.tryLock(0):
            raise OSError('Could not lock recovery session')
        _SESSIONS[key] = (folder, lock)
    return _SESSIONS[key][0]


def atomic_write(path, data):
    path = Path(path)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix='.write-', dir=path.parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def write_meta(folder, metadata):
    atomic_write(folder / 'meta.json', json.dumps(dict(metadata, version=1, updated=time.time())).encode())


def new_entry():
    folder = session_dir() / uuid.uuid4().hex
    folder.mkdir(mode=0o700)
    return folder


def discard_entry(folder):
    """Called only for explicit save/discard, never simply for process shutdown."""
    shutil.rmtree(folder, ignore_errors=True)


class DraftRecord:
    def __init__(self):
        self.folder = new_entry()
        self.error = ''
        self._condition = threading.Condition()
        self._pending = None
        self._discard = False
        self._stop = False
        self._writing = False
        self.thread = threading.Thread(target=self._run, daemon=True, name='yara-recovery')
        self.thread.start()

    def submit(self, text, metadata):
        with self._condition:
            self._pending = (text, metadata)
            self._condition.notify()

    def discard(self):
        with self._condition:
            self._discard = self._stop = True
            self._pending = None
            self._condition.notify()

    def finish(self):
        with self._condition:
            self._stop = True
            self._condition.notify()

    def _run(self):
        try:
            while True:
                with self._condition:
                    while self._pending is None and not self._stop:
                        self._condition.wait()
                    if self._discard or (self._stop and self._pending is None):
                        break
                    text, metadata = self._pending
                    self._pending = None
                    self._writing = True
                try:
                    atomic_write(self.folder / 'draft.yar', text.encode('utf-8'))
                    write_meta(self.folder, dict(metadata, kind='yara'))
                    self.error = ''
                except Exception as exc:
                    self.error = str(exc)
                finally:
                    self._writing = False
        finally:
            if self._discard:
                discard_entry(self.folder)


class UnavailableRecovery:
    def __init__(self, error):
        self.error = error

    def record(self, *args):
        pass

    def discard(self):
        pass

    def finish(self):
        pass


class HexJournal:
    """One immutable baseline, then transactional byte replacement records.

    Disk I/O is off the GUI thread. A bounded pending-patch budget prevents a
    slow disk from retaining unlimited transformed buffers in memory.
    """
    MAX_PENDING = 64 * 1024 * 1024

    def __init__(self, source, name, expected_stat=None):
        self.folder = new_entry()
        self.name = name
        self.error = ''
        self.ready = False
        self.saved_sequence = 0
        self.sequence = 0
        self._queue = queue.Queue()
        self._discard = threading.Event()
        self._lock = threading.Lock()
        self._pending_bytes = 0
        self._source = source
        # Open before the buffer releases its mapping or the user changes files.
        self._stream = None if isinstance(source, bytes) else open(source, 'rb')
        if expected_stat is not None and self._stream is not None:
            stat = os.fstat(self._stream.fileno())
            if (stat.st_size, stat.st_mtime_ns, stat.st_ino) != expected_stat:
                self._stream.close()
                raise OSError('Saved baseline changed externally; save this working copy again to restart recovery')
        self.thread = threading.Thread(target=self._run, daemon=True, name='hex-recovery')
        self.thread.start()

    def record(self, offset, old_length, new_bytes):
        with self._lock:
            if self.error or self._pending_bytes + len(new_bytes) + 256 > self.MAX_PENDING:
                self.error = self.error or 'Recovery backlog exceeds 64 MiB. Save this file to protect the latest edits.'
                return
            self.sequence += 1
            self._pending_bytes += len(new_bytes) + 256
            self._queue.put((self.sequence, offset, old_length, new_bytes))

    def discard(self):
        self._discard.set()
        self._queue.put(None)
        if not self.thread.is_alive():
            IO_POOL.submit(discard_entry, self.folder)

    def finish(self):
        self._queue.put(None)

    def _run(self):
        connection = None
        try:
            digest = hashlib.sha256()
            temporary = self.folder / 'base.tmp'
            with temporary.open('wb') as out:
                if self._stream is not None:
                    original = os.fstat(self._stream.fileno())
                    while chunk := self._stream.read(COPY_CHUNK):
                        if self._discard.is_set():
                            return
                        out.write(chunk)
                        digest.update(chunk)
                    current = os.fstat(self._stream.fileno())
                    if (original.st_size, original.st_mtime_ns) != (current.st_size, current.st_mtime_ns):
                        raise OSError('Original changed while preparing recovery; save the current file')
                else:
                    for pos in range(0, len(self._source), COPY_CHUNK):
                        if self._discard.is_set():
                            return
                        chunk = self._source[pos:pos+COPY_CHUNK]
                        out.write(chunk)
                        digest.update(chunk)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, self.folder / 'base.bin')
            self._source = None
            if self._stream is not None:
                self._stream.close()
                self._stream = None
            connection = sqlite3.connect(self.folder / 'edits.sqlite')
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('CREATE TABLE edits (seq INTEGER PRIMARY KEY, offset INTEGER, removed INTEGER, data BLOB)')
            connection.commit()
            write_meta(self.folder, dict(kind='hex', source=self.name,
                       base_sha256=digest.hexdigest()))
            self.ready = True
            while not self._discard.is_set():
                edit = self._queue.get()
                if edit is None:
                    break
                with connection:
                    connection.execute('INSERT INTO edits VALUES (?, ?, ?, ?)', edit)
                with self._lock:
                    self.saved_sequence = edit[0]
                    self._pending_bytes -= len(edit[3]) + 256
        except Exception as exc:
            self.error = str(exc)
        finally:
            self._source = None
            if self._stream is not None:
                self._stream.close()
            if connection is not None:
                connection.close()
            if self._discard.is_set():
                discard_entry(self.folder)


def recoverable_entries():
    root = recovery_root()
    if not root.exists():
        return []
    active = {str(folder) for folder, _ in _SESSIONS.values()}
    entries = []
    for folder in root.iterdir():
        if folder.name == 'restored' or not folder.is_dir() or folder.is_symlink() or str(folder) in active:
            continue
        if str(folder) not in _CLAIMS:
            lock = QLockFile(str(folder / 'session.lock'))
            lock.setStaleLockTime(0)
            if not lock.tryLock(0):
                continue
            _CLAIMS[str(folder)] = lock
        for manifest in folder.glob('*/meta.json'):
            try:
                metadata = json.loads(manifest.read_text())
                if metadata.get('version') != 1 or metadata.get('kind') not in ('yara', 'hex'):
                    continue
                entries.append((manifest.parent, metadata))
            except (OSError, ValueError):
                continue
    return sorted(entries, key=lambda item: item[1].get('updated', 0), reverse=True)


def restore_hex(folder):
    """Reconstruct using source slices and SQLite BLOB slices, not a huge bytearray."""
    folder = Path(folder)
    metadata = json.loads((folder / 'meta.json').read_text())
    digest = hashlib.sha256()
    with (folder / 'base.bin').open('rb') as base:
        while chunk := base.read(COPY_CHUNK):
            digest.update(chunk)
    if digest.hexdigest() != metadata['base_sha256']:
        raise ValueError('Recovery baseline is damaged; the original journal has been retained')
    connection = sqlite3.connect((folder / 'edits.sqlite').as_uri()+'?mode=ro', uri=True)
    try:
        size = (folder / 'base.bin').stat().st_size
        pieces = [(0, 0, size)]  # (0=baseline or edit sequence, source offset, length)
        for seq, offset, removed, added in connection.execute('SELECT seq, offset, removed, length(data) FROM edits ORDER BY seq'):
            if offset < 0 or removed < 0 or offset + removed > size:
                raise ValueError('Invalid recovery edit range')
            before, after, position = [], [], 0
            for source, start, length in pieces:
                end = position + length
                if position < offset:
                    keep = min(length, offset-position)
                    before.append((source, start, keep))
                if end > offset+removed:
                    skip = max(0, offset+removed-position)
                    after.append((source, start+skip, length-skip))
                position = end
            pieces = before + ([(seq, 0, added)] if added else []) + after
            size += added-removed
        output_dir = recovery_root() / 'restored'
        output_dir.mkdir(exist_ok=True, mode=0o700)
        destination = output_dir / (uuid.uuid4().hex + '.bin')
        temporary = destination.with_suffix('.tmp')
        try:
            with (folder / 'base.bin').open('rb') as base, temporary.open('wb') as out:
                for source, offset, length in pieces:
                    stream = connection.blobopen('edits', 'data', source, readonly=True) if source else base
                    try:
                        stream.seek(offset)
                        while length:
                            chunk = stream.read(min(length, COPY_CHUNK))
                            if not chunk:
                                raise ValueError('Truncated recovery data')
                            out.write(chunk)
                            length -= len(chunk)
                    finally:
                        if source:
                            stream.close()
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return destination
    finally:
        connection.close()
