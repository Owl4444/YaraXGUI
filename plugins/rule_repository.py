"""Rule Repository plugin — SQLite-backed YARA rule storage.

Provides:
  - GUI dock panel for browsing/searching/uploading rules
  - API endpoints for CRUD + full-text search + bulk import
"""

from __future__ import annotations

import os
import sqlite3
import threading
import functools
import sys
from pathlib import Path

# Ensure project root is importable
_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from plugins.base import register_plugin

plugin = register_plugin(
    name="rule_repository",
    description="SQLite-backed YARA rule storage with full-text search",
    version="1.0.0",
    author="YaraXGUI",
)

# ── GUI Dock ─────────────────────────────────────────────────────

@plugin.dock(title="Rule Repository", area="right")
def create_dock(ctx):
    from yaraxgui.repository.dock import RuleRepoDock
    dock = RuleRepoDock()
    dock.rule_load_requested.connect(ctx.load_rule_to_editor)
    dock._get_editor_text = ctx.get_editor_text
    dock._edit_repository_rule = ctx.edit_repository_rule
    dock._save_setting = ctx.save_setting
    dock._get_setting = ctx.get_setting
    # Pre-fill remote server fields from saved settings (local is primary)
    try:
        url = ctx.get_setting('repo_server_url', '')
        if url:
            dock.set_server(url)  # just fills inputs, stays in Local
    except Exception:
        pass
    return dock


# ── API Endpoints ────────────────────────────────────────────────

_repo = None
_repo_lock = threading.RLock()


def serialized(handler):
    @functools.wraps(handler)
    def wrapped(*args, **kwargs):
        with _repo_lock:
            return handler(*args, **kwargs)
    return wrapped


def _get_repo():
    global _repo
    if _repo is None:
        from api.rule_repo import RuleRepository
        db_path = os.environ.get(
            "YARAXGUI_REPO_DB",
            str(Path(__file__).parent.parent / "api" / "rules.db"))
        _repo = RuleRepository(db_path)
        from api.security import number
        maximum = number(os.environ, 'YARAXGUI_REPO_MAX_MB', 256, maximum=102400) * 1024**2
        page_size = _repo._conn.execute('PRAGMA page_size').fetchone()[0]
        _repo._conn.execute(f'PRAGMA max_page_count={maximum // page_size}')
    return _repo


# -- Models (plugin-local) --

from pydantic import BaseModel, Field, model_validator


class BoundedModel(BaseModel):
    @model_validator(mode="after")
    def bound_fields(self):
        for name, value in self.model_dump().items():
            limit = 1048576 if name in ("rule_text", "expected_rule_text", "yara_text") else 4096
            if isinstance(value, str) and len(value.encode("utf-8")) > limit:
                raise ValueError(f"{name} exceeds {limit} bytes")
        return self


class _RepoRuleCreate(BoundedModel):
    name: str = Field(..., description="Rule name")
    rule_text: str = Field(..., description="Full YARA source code")
    family: str = Field("", description="Malware family")
    tags: str = Field("", description="Comma-separated tags")
    author: str = Field("", description="Rule author")
    description: str = Field("", description="Rule description")
    source: str = Field("", description="Origin")


class _RepoRuleUpdate(BoundedModel):
    name: str | None = None
    rule_text: str | None = None
    expected_rule_text: str | None = None
    family: str | None = None
    tags: str | None = None
    author: str | None = None
    description: str | None = None
    source: str | None = None


class _RepoImportRequest(BoundedModel):
    yara_text: str = Field(..., description="Multi-rule YARA source")
    source: str = Field("", description="Origin label")
    author: str = Field("", description="Author")
    family: str = Field("", description="Family")


# -- Routes --

from fastapi import HTTPException, Query
from api.rule_repo import RuleConflictError


@plugin.api("GET", "/repo/rules", tags=["Repository"])
@serialized
def repo_search(q: str | None = Query(None, max_length=1024), family: str | None = None,
                      tags: str | None = None, author: str | None = None,
                      source: str | None = None,
                      limit: int = Query(50, ge=1, le=250), offset: int = Query(0, ge=0, le=1000000)):
    """Search rules in the repository."""
    try:
        rows = _get_repo().search(q=q, family=family, tags=tags,
                                  author=author, source=source,
                                  limit=limit, offset=offset, max_bytes=8 * 1024**2)
        return rows
    except OverflowError as e:
        raise HTTPException(413, str(e)) from e
    except sqlite3.OperationalError as e:
        raise HTTPException(400, str(e)) from e


@plugin.api("POST", "/repo/rules", tags=["Repository"])
@serialized
def repo_add(req: _RepoRuleCreate):
    """Add a new rule."""
    try:
        rid = _get_repo().add(
            name=req.name, rule_text=req.rule_text,
            family=req.family, tags=req.tags,
            author=req.author, description=req.description,
            source=req.source)
        return {"id": rid, "message": "Rule added"}
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            raise HTTPException(409, f"Rule '{req.name}' already exists "
                                     f"in family '{req.family}'")
        raise HTTPException(400, str(e))


@plugin.api("POST", "/repo/rules/import", tags=["Repository"])
@serialized
def repo_import(req: _RepoImportRequest):
    """Bulk import rules from a multi-rule YARA file."""
    from api.yaraxgui_api import _runner
    from api.workers import WorkerBusy
    try:
        rows = _runner.run('repo_split', {'text': req.yara_text})
    except WorkerBusy as exc:
        raise HTTPException(429, str(exc)) from exc
    except (ValueError, RuntimeError, TimeoutError) as exc:
        raise HTTPException(422, str(exc)) from exc
    imported, skipped = 0, 0
    repo = _get_repo()
    try:
        for name, source in rows:
            try:
                repo.add(name=name, rule_text=source, source=req.source,
                         author=req.author, family=req.family)
                imported += 1
            except sqlite3.IntegrityError:
                skipped += 1
    except sqlite3.OperationalError as exc:
        raise HTTPException(413, 'Repository storage limit reached; remove rules or raise the server quota') from exc
    return {'imported': imported, 'skipped': skipped, 'errors': []}


@plugin.api("GET", "/repo/rules/{rule_id}", tags=["Repository"])
@serialized
def repo_get(rule_id: int):
    """Get a single rule by ID."""
    rule = _get_repo().get(rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule


@plugin.api("PUT", "/repo/rules/{rule_id}", tags=["Repository"])
@serialized
def repo_update(rule_id: int, req: _RepoRuleUpdate):
    """Update an existing rule."""
    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    if not (fields.keys() - {"expected_rule_text"}):
        raise HTTPException(400, "No fields to update")
    try:
        ok = _get_repo().update(rule_id, **fields)
    except RuleConflictError as e:
        raise HTTPException(409, str(e)) from e
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, "A rule with that name and family already exists") from e
    if not ok:
        raise HTTPException(404, "Rule not found")
    return {"message": "Rule updated"}


@plugin.api("DELETE", "/repo/rules/{rule_id}", tags=["Repository"])
@serialized
def repo_delete(rule_id: int):
    """Delete a rule."""
    ok = _get_repo().delete(rule_id)
    if not ok:
        raise HTTPException(404, "Rule not found")
    return {"message": "Rule deleted"}


@plugin.api("GET", "/repo/stats", tags=["Repository"])
@serialized
def repo_stats():
    """Repository statistics."""
    return _get_repo().stats()


@plugin.api("GET", "/repo/families", tags=["Repository"])
@serialized
def repo_families():
    """List distinct malware families."""
    return _get_repo().families()


@plugin.api("GET", "/repo/tags", tags=["Repository"])
@serialized
def repo_tags():
    """List distinct tags."""
    return _get_repo().tags()
