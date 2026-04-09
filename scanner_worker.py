# This Python file uses the following encoding: utf-8

"""
ScanWorker — QThread wrapper around YaraScanner so large file-set scans
don't hang the UI.

Keeps ``scanner.py`` Qt-free: this module is the thin bridge between the
pure-logic scanner and the Qt main window.

Signals
-------
progress(scanned:int, total:int, filename:str)
    Emitted after each file is processed.  ``filename`` is the base name
    of the file that just finished scanning (useful for status text).
result_ready(dict)
    Emitted exactly once when the thread finishes.  Mirrors the dict
    returned by :meth:`YaraScanner.scan_files` plus a ``cancelled`` bool.
error(str)
    Emitted if the worker itself crashes (not per-file errors — those are
    bundled into the result under ``error_messages``).
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QThread, Signal

from scanner import SizeBounds, YaraScanner


class ScanWorker(QThread):
    """Runs :meth:`YaraScanner.scan_file` over a file list on a worker thread."""

    progress = Signal(int, int, str)     # scanned, total, current_file_name
    result_ready = Signal(dict)          # hits/misses/stats/error_messages/cancelled
    error = Signal(str)                  # fatal worker error

    def __init__(self,
                 scanner: YaraScanner,
                 rules,
                 files: List[Path],
                 parent=None,
                 size_bounds: Optional[SizeBounds] = None):
        super().__init__(parent)
        self._scanner = scanner
        self._rules = rules
        self._files = list(files)
        self._size_bounds = size_bounds or SizeBounds()
        self._cancel = False

    def cancel(self):
        """Request a graceful stop. The worker checks this between files."""
        self._cancel = True

    def is_cancelled(self) -> bool:
        return self._cancel

    def run(self):
        """Scan loop (runs on the worker thread)."""
        try:
            hits: list = []
            misses: list = []
            error_messages: list = []
            stats = {'scanned': 0, 'matches': 0, 'errors': 0, 'skipped': 0}
            total = len(self._files)
            bounds = self._size_bounds

            for idx, file_path in enumerate(self._files, start=1):
                if self._cancel:
                    break

                stats['scanned'] += 1

                # Pre-filter by file size. If the ruleset has a usable
                # upper/lower bound on `filesize`, files outside that
                # range cannot possibly match any rule — skip them
                # without reading their contents.
                if bounds.is_useful():
                    try:
                        fsize = file_path.stat().st_size
                    except OSError:
                        fsize = None
                    if fsize is not None and bounds.can_skip(fsize):
                        stats['skipped'] += 1
                        misses.append({
                            'filename': file_path.name,
                            'filepath': str(file_path),
                            'md5': '',
                            'sha1': '',
                            'sha256': '',
                            'skipped': True,
                            'skip_reason': (
                                f"filesize {fsize} bytes outside rule bounds"
                            ),
                            'file_size': fsize,
                        })
                        self.progress.emit(idx, total, file_path.name)
                        continue

                try:
                    result = self._scanner.scan_file(self._rules, file_path)
                    if result.get('hit'):
                        stats['matches'] += 1
                        result.pop('hit', None)
                        hits.append(result)
                    else:
                        result.pop('hit', None)
                        misses.append(result)
                except PermissionError:
                    stats['errors'] += 1
                except Exception as e:
                    stats['errors'] += 1
                    error_messages.append(
                        f"\u2717 Error scanning {file_path}: {e}"
                    )

                # Emit progress AFTER the file is done so "scanned" is accurate.
                # Qt queues this across threads automatically.
                self.progress.emit(idx, total, file_path.name)

            self.result_ready.emit({
                'hits': hits,
                'misses': misses,
                'stats': stats,
                'error_messages': error_messages,
                'cancelled': self._cancel,
            })
        except Exception as e:
            # Catch-all: something in the scanner itself blew up.
            self.error.emit(f"Scanner thread crashed: {e}")
