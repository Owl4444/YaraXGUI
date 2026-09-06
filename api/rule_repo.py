"""YARA Rule Repository — SQLite backend with full-text search.

Stores YARA rules with metadata (family, tags, author, etc.) and
provides instant search via FTS5.  The database is auto-created on
first use.
"""

from __future__ import annotations

import re
import json
from contextlib import closing
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    family        TEXT DEFAULT '',
    tags          TEXT DEFAULT '',
    author        TEXT DEFAULT '',
    description   TEXT DEFAULT '',
    source        TEXT DEFAULT '',
    rule_text     TEXT NOT NULL,
    date_added    TEXT NOT NULL,
    date_modified TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_name_family
    ON rules(name, family);

-- FTS5 virtual table for instant full-text search
CREATE VIRTUAL TABLE IF NOT EXISTS rules_fts USING fts5(
    name, family, tags, author, description, source, rule_text,
    content='rules', content_rowid='id'
);

-- Keep FTS in sync via triggers
CREATE TRIGGER IF NOT EXISTS rules_ai AFTER INSERT ON rules BEGIN
    INSERT INTO rules_fts(rowid, name, family, tags, author,
                          description, source, rule_text)
    VALUES (new.id, new.name, new.family, new.tags, new.author,
            new.description, new.source, new.rule_text);
END;

CREATE TRIGGER IF NOT EXISTS rules_ad AFTER DELETE ON rules BEGIN
    INSERT INTO rules_fts(rules_fts, rowid, name, family, tags,
                          author, description, source, rule_text)
    VALUES ('delete', old.id, old.name, old.family, old.tags,
            old.author, old.description, old.source, old.rule_text);
END;

CREATE TRIGGER IF NOT EXISTS rules_au AFTER UPDATE ON rules BEGIN
    INSERT INTO rules_fts(rules_fts, rowid, name, family, tags,
                          author, description, source, rule_text)
    VALUES ('delete', old.id, old.name, old.family, old.tags,
            old.author, old.description, old.source, old.rule_text);
    INSERT INTO rules_fts(rowid, name, family, tags, author,
                          description, source, rule_text)
    VALUES (new.id, new.name, new.family, new.tags, new.author,
            new.description, new.source, new.rule_text);
END;
"""

# Regex to split a multi-rule YARA file into individual rules
_RULE_SPLIT_RE = re.compile(
    r'(?:^|\n)'                         # start of string or newline
    r'((?:private\s+|global\s+)*'       # optional modifiers
    r'rule\s+'                          # 'rule' keyword
    r'(\w+)'                            # rule name (capture group 2)
    r'(?:\s*:\s*[\w\s]+)?'              # optional tags
    r'\s*\{)',                           # opening brace
    re.MULTILINE,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


class RuleConflictError(ValueError):
    """A repository update would overwrite another editor's changes."""


class RuleRepository:
    """SQLite-backed YARA rule storage with full-text search."""

    def __init__(self, db_path: str = "rules.db"):
        self._db_path = str(db_path)
        if self._db_path != ":memory:":
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ── Search / Read ────────────────────────────────────────────

    def search(self, q: str | None = None,
               family: str | None = None,
               tags: str | None = None,
               author: str | None = None,
               source: str | None = None,
               limit: int = 50, offset: int = 0, max_bytes: int | None = None) -> list[dict]:
        """Search rules. *q* uses FTS5 full-text; other params filter."""
        if q:
            # FTS5 search across all indexed fields
            sql = """
                SELECT r.* FROM rules r
                JOIN rules_fts f ON r.id = f.rowid
                WHERE rules_fts MATCH ?
            """
            params: list[Any] = [q]
        else:
            sql = "SELECT r.* FROM rules r WHERE 1=1"
            params = []

        if family:
            sql += " AND r.family = ?"
            params.append(family)
        if tags:
            # Match all of the provided tags
            for tag in tags.split(","):
                tag = tag.strip()
                if tag:
                    sql += " AND r.tags LIKE ?"
                    params.append(f"%{tag}%")
        if author:
            sql += " AND r.author = ?"
            params.append(author)
        if source:
            sql += " AND r.source = ?"
            params.append(source)

        sql += " ORDER BY r.date_modified DESC, r.id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        result, used = [], 2
        with closing(self._conn.execute(sql, params)) as cursor:
            for row in cursor:
                item = _row_to_dict(row)
                if max_bytes is not None:
                    used += len(json.dumps(item).encode('utf-8')) + 2
                    if used > max_bytes:
                        raise OverflowError('Search results exceed the response limit; reduce the page size')
                result.append(item)
        return result

    def get(self, rule_id: int) -> dict | None:
        """Get a single rule by ID."""
        row = self._conn.execute(
            "SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
        return _row_to_dict(row) if row else None

    # ── Create / Update / Delete ─────────────────────────────────

    def add(self, name: str, rule_text: str,
            family: str = "", tags: str = "",
            author: str = "", description: str = "",
            source: str = "") -> int:
        """Insert a new rule. Returns the new ID."""
        now = _now()
        with self._conn:
            cur = self._conn.execute(
                """INSERT INTO rules
                   (name, family, tags, author, description, source,
                    rule_text, date_added, date_modified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, family, tags, author, description, source,
                 rule_text, now, now))
        return cur.lastrowid

    def update(self, rule_id: int, *, expected_rule_text: str | None = None, **fields) -> bool:
        """Update fields on an existing rule."""
        allowed = {"name", "family", "tags", "author", "description",
                   "source", "rule_text"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return False
        updates["date_modified"] = _now()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [rule_id]
        condition = "id = ?"
        if expected_rule_text is not None:
            condition += " AND rule_text = ?"
            values.append(expected_rule_text)
        with self._conn:
            cur = self._conn.execute(
                f"UPDATE rules SET {set_clause} WHERE {condition}", values)
            if cur.rowcount == 0 and expected_rule_text is not None and self.get(rule_id):
                raise RuleConflictError(
                    'This rule changed in the repository. Your edits were not saved; '
                    'save a copy before reloading the repository version.')
        return cur.rowcount > 0

    def delete(self, rule_id: int) -> bool:
        """Delete a rule by ID."""
        with self._conn:
            cur = self._conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        return cur.rowcount > 0

    # ── Bulk import ──────────────────────────────────────────────

    def import_file(self, yara_text: str, source: str = "",
                    author: str = "", family: str = "") -> dict:
        """Parse a multi-rule YARA file and insert each rule.

        Returns ``{"imported": N, "skipped": N, "errors": [...]}``.
        """
        rules = self._split_rules(yara_text)
        imported = 0
        skipped = 0
        errors: list[str] = []

        for name, text in rules:
            try:
                self.add(name=name, rule_text=text.strip(),
                         source=source, author=author, family=family)
                imported += 1
            except sqlite3.IntegrityError:
                skipped += 1  # duplicate name+family
            except Exception as e:
                errors.append(f"{name}: {e}")

        return {"imported": imported, "skipped": skipped, "errors": errors}

    @staticmethod
    def _split_rules(yara_text: str) -> list[tuple[str, str]]:
        """Split YARA source into (name, full_rule_text) pairs."""
        results: list[tuple[str, str]] = []
        # Find all rule starts
        starts = []
        for m in _RULE_SPLIT_RE.finditer(yara_text):
            starts.append((m.start(), m.group(2)))  # (offset, name)

        if not starts:
            # Single rule or unparseable — use whole text
            name_match = re.search(r'rule\s+(\w+)', yara_text)
            name = name_match.group(1) if name_match else "unnamed"
            return [(name, yara_text.strip())]

        for i, (start, name) in enumerate(starts):
            if i + 1 < len(starts):
                end = starts[i + 1][0]
            else:
                end = len(yara_text)
            rule_text = yara_text[start:end].strip()
            results.append((name, rule_text))

        return results

    # ── Metadata queries ─────────────────────────────────────────

    def stats(self) -> dict:
        """Repository statistics."""
        total = self._conn.execute(
            "SELECT COUNT(*) FROM rules").fetchone()[0]
        families = self._conn.execute(
            "SELECT COUNT(DISTINCT family) FROM rules "
            "WHERE family != ''").fetchone()[0]
        sources = self._conn.execute(
            "SELECT COUNT(DISTINCT source) FROM rules "
            "WHERE source != ''").fetchone()[0]
        return {"total_rules": total, "families": families,
                "sources": sources}

    def families(self) -> list[str]:
        """List distinct family names."""
        rows = self._conn.execute(
            "SELECT DISTINCT family FROM rules "
            "WHERE family != '' ORDER BY family").fetchall()
        return [r[0] for r in rows]

    def tags(self) -> list[str]:
        """List distinct tags (flattened from comma-separated)."""
        rows = self._conn.execute(
            "SELECT DISTINCT tags FROM rules WHERE tags != ''").fetchall()
        tag_set: set[str] = set()
        for (tags_str,) in rows:
            for t in tags_str.split(","):
                t = t.strip()
                if t:
                    tag_set.add(t)
        return sorted(tag_set)

    def close(self):
        self._conn.close()
