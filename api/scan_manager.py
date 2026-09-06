"""Scan job state and pure helpers shared with bounded worker processes.

The legacy unbounded thread/network implementation has been removed.
"""
from __future__ import annotations

import fnmatch
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ScanJob:
    """State container for a single scan job."""

    __slots__ = (
        "job_id", "status", "rule_text", "paths", "recursive",
        "exclusions", "progress", "results", "error",
        "created_at", "completed_at", "_cancel_event",
        "source", "mwdb_url", "mwdb_token", "mwdb_query",
        "mwdb_limit", "mwdb_batch_size", "mwdb_file_hash",
        "include_misses", "parallel_downloads",
    )

    def __init__(self, rule_text: str, paths: list[str],
                 recursive: bool = True, exclusions: list[str] | None = None,
                 source: str = "local"):
        self.job_id: str = uuid.uuid4().hex[:12]
        self.status: str = "queued"
        self.rule_text = rule_text
        self.paths = paths
        self.recursive = recursive
        self.exclusions = exclusions or []
        self.progress: dict[str, Any] = {"scanned": 0, "total": 0, "current_file": ""}
        self.results: dict[str, Any] = {}
        self.error: str = ""
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.completed_at: str | None = None
        self._cancel_event = threading.Event()
        self.source = source  # "local" or "mwdb"
        # MWDB-specific fields (set by create_mwdb_job)
        self.mwdb_url: str = ""
        self.mwdb_token: str = ""
        self.mwdb_query: str | None = None
        self.mwdb_limit: int = 100
        self.mwdb_batch_size: int = 50
        self.mwdb_file_hash: str | None = None
        self.include_misses: bool = True
        self.parallel_downloads: int = 4

    def cancel(self):
        self._cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def to_status_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "progress": self.progress.copy(),
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }

    def to_results_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "status": self.status,
            **self.results,
        }


def is_excluded(path: Path, exclusions: list[str]) -> bool:
    name = path.name
    for pat in exclusions:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(str(path), pat):
            return True
    return False


def embed_match_snippets(result: dict, file_data: bytes):
    """Extract matched byte regions and embed as base64 in the result.

    Each pattern match gets ``data_preview`` (ASCII) and ``hex_dump``
    fields so the client can display them without the full file.
    """
    import base64
    if not file_data:
        return
    for rule in result.get("matched_rules", []):
        for pat in rule.get("patterns", []):
            for m in pat.get("matches", []):
                off = m.get("offset", 0)
                ln = m.get("length", 0)
                if 0 <= off < len(file_data) and ln > 0:
                    snippet = file_data[off:off + min(ln, 1024)]
                    # Hex dump
                    m["hex_dump"] = " ".join(
                        f"{b:02X}" for b in snippet[:64])
                    # ASCII preview
                    m["data_preview"] = "".join(
                        chr(b) if 0x20 <= b < 0x7F else "."
                        for b in snippet[:64])
                    # Full snippet as base64 (for hex editor)
                    if ln <= 1024:
                        m["snippet_b64"] = base64.b64encode(
                            snippet).decode("ascii")


class ScanManager:
    """Compatibility constructor; all jobs use the secured process manager."""
    def __new__(cls, *args, **kwargs):
        from .jobs import SecureScanManager
        return SecureScanManager(*args, **kwargs)
