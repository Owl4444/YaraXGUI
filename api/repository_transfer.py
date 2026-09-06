"""Offline repository backup/export/restore; no HTTP endpoint or desktop deps.

Backups use SQLite's online backup API, including committed WAL transactions.
Restore rebuilds the known schema instead of installing SQL from an input file.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time
import zipfile

from api.rule_repo import RuleRepository

COLUMNS = ('id', 'name', 'family', 'tags', 'author', 'description', 'source',
           'rule_text', 'date_added', 'date_modified')


def read_database(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    connection.execute('PRAGMA trusted_schema=OFF')
    return connection


def copy_database(source, target):
    deadline = time.monotonic() + 60

    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise TimeoutError('Database remained busy for 60 seconds; retry when writes are quieter')

    source.backup(target, pages=256, progress=progress, sleep=0.1)


def backup_database(database, destination):
    """Create a new standalone snapshot; never overwrite an existing file."""
    destination = Path(destination)
    with closing(read_database(database)) as source:
        # Reserve exclusively, including protection against existing symlinks.
        with destination.open('xb'):
            pass
        try:
            with closing(sqlite3.connect(destination)) as target:
                copy_database(source, target)
                target.execute('PRAGMA journal_mode=DELETE')
        except BaseException:
            destination.unlink(missing_ok=True)
            raise


def export_database(database, destination):
    """Readable ZIP: exact source per rule, plus all repository metadata."""
    with tempfile.TemporaryDirectory(prefix='yaraxgui-export-') as folder:
        snapshot = Path(folder) / 'rules.db'
        backup_database(database, snapshot)
        destination = Path(destination)
        with destination.open('xb') as output:
            try:
                with closing(read_database(snapshot)) as source:
                    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                        source.row_factory = sqlite3.Row
                        # Numeric IDs avoid unsafe names and duplicate name/family collisions.
                        for row in source.execute('SELECT id, rule_text FROM rules ORDER BY id'):
                            archive.writestr(f'rules/{row["id"]}.yar', row['rule_text'].encode('utf-8'))
                        with archive.open('manifest.json', 'w') as manifest:
                            manifest.write(b'{"format":"yaraxgui-rule-export","version":1,"rules":[')
                            separator = b''
                            for row in source.execute('SELECT * FROM rules ORDER BY id'):
                                entry = dict(row)
                                del entry['rule_text']
                                entry['file'] = f'rules/{row["id"]}.yar'
                                manifest.write(separator + json.dumps(entry, ensure_ascii=False).encode('utf-8'))
                                separator = b','
                            manifest.write(b']}')
            except BaseException:
                output.close()
                destination.unlink(missing_ok=True)
                raise


def restore_database(backup, database, *, replace=False):
    """Restore rows/IDs/dates and rebuild FTS; the API must be stopped first.

    Source triggers/views are never installed. The final SQLite backup operation
    replaces the destination in a transaction, without swapping a live inode.
    """
    database = Path(database)
    if database.exists() and not replace:
        raise FileExistsError('Repository already exists; back it up, then use --replace to replace it')
    if database.is_symlink():
        raise ValueError('Refusing to restore through a database symlink')
    if Path(backup).resolve() == database.resolve():
        raise ValueError('Backup and destination must be different files')
    with tempfile.TemporaryDirectory(prefix='yaraxgui-restore-') as folder:
        # First snapshot the input so all validation/copying sees one version.
        snapshot = Path(folder) / 'input.db'
        backup_database(backup, snapshot)
        with closing(read_database(snapshot)) as source:
            if source.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise ValueError('Backup failed SQLite integrity checks')
            table = source.execute("SELECT type FROM sqlite_schema WHERE name='rules'").fetchone()
            columns = tuple(row[1] for row in source.execute('PRAGMA table_info(rules)'))
            if table != ('table',) or columns != COLUMNS:
                raise ValueError('Unsupported repository backup schema')
            clean = RuleRepository(Path(folder) / 'clean.db')
            try:
                with clean._conn:
                    clean._conn.executemany(
                        'INSERT INTO rules (' + ','.join(COLUMNS) + ') VALUES (' + ','.join('?' for _ in COLUMNS) + ')',
                        source.execute('SELECT ' + ','.join(COLUMNS) + ' FROM rules ORDER BY id'))
                    # Preserve the high water mark even when the last rules were deleted.
                    sequence = source.execute("SELECT seq FROM sqlite_sequence WHERE name='rules'").fetchone()
                    if sequence is not None:
                        if type(sequence[0]) is not int or sequence[0] < 0:
                            raise ValueError('Invalid repository ID sequence')
                        clean._conn.execute("DELETE FROM sqlite_sequence WHERE name='rules'")
                        clean._conn.execute("INSERT INTO sqlite_sequence(name,seq) VALUES('rules',?)", sequence)
                created = False
                try:
                    # Check again after validating; never clobber a newly appeared file.
                    try:
                        with database.open('xb'):
                            pass
                        created = True
                    except FileExistsError:
                        if not replace or database.is_symlink():
                            raise
                    with closing(sqlite3.connect(database)) as target:
                        copy_database(clean._conn, target)
                except BaseException:
                    if created:
                        database.unlink(missing_ok=True)
                    raise
            finally:
                clean.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('backup', 'export', 'restore'))
    parser.add_argument('file', help='File path, or - for binary stdin/stdout')
    parser.add_argument('--database', default=os.environ.get(
        'YARAXGUI_REPO_DB', str(Path(__file__).parent / 'rules.db')))
    parser.add_argument('--replace', action='store_true', help='Allow restore to replace an existing repository')
    args = parser.parse_args(argv)
    try:
        with tempfile.TemporaryDirectory(prefix='yaraxgui-transfer-') as folder:
            path = Path(folder) / 'transfer' if args.file == '-' else Path(args.file)
            if args.action == 'restore':
                if args.file == '-':
                    with path.open('xb') as target:
                        shutil.copyfileobj(sys.stdin.buffer, target)
                restore_database(path, args.database, replace=args.replace)
            else:
                operation = backup_database if args.action == 'backup' else export_database
                operation(args.database, path)
                if args.file == '-':
                    with path.open('rb') as source:
                        shutil.copyfileobj(source, sys.stdout.buffer)
    except (OSError, sqlite3.Error, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
