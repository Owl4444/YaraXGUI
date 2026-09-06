"""Persistent desktop repository location and migration from older releases."""

from __future__ import annotations

import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from yaraxgui.paths import resource_root
from tempfile import TemporaryDirectory


def local_database_path() -> Path:
    """Use the same writable location for source and packaged applications."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library/Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
        if not base.is_absolute():
            base = Path.home() / ".local/share"
    return base / "YaraXGUI" / "local_rules.db"


def prepare_local_database() -> Path:
    """Copy an existing legacy database on first use, preserving its original.

    SQLite backup includes committed WAL contents. Publishing the completed
    copy atomically keeps a failed migration from leaving a partial database.
    """
    destination = local_database_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        return destination

    candidates = [resource_root() / "config/local_rules.db"]
    if getattr(sys, "frozen", False):
        candidates.insert(0, Path(sys.executable).resolve().parent / "config/local_rules.db")
    for legacy in candidates:
        if not legacy.is_file():
            continue
        with TemporaryDirectory(prefix="rule-migration-", dir=destination.parent) as tmp:
            snapshot = Path(tmp) / "local_rules.db"
            with closing(sqlite3.connect(legacy.as_uri() + "?mode=ro", uri=True)) as source:
                with closing(sqlite3.connect(snapshot)) as target:
                    source.backup(target)
            # Do not replace a database created by another application instance.
            try:
                os.link(snapshot, destination)
            except FileExistsError:
                pass
        break
    return destination
