from pathlib import Path
import json
import sqlite3
import subprocess
import sys
import zipfile

import pytest

from api.rule_repo import RuleRepository
from api.repository_transfer import backup_database, export_database, restore_database
from scripts.repository import transfer, compose_command


@pytest.fixture
def repository(tmp_path):
    repo = RuleRepository(tmp_path / 'live.db')
    repo.add('same', 'import "pe"\r\nrule same { condition: pe.is_pe }\r\n',
             family='雪', tags='one,two', author='author', description='needle', source='original')
    repo.add('same', 'rule same { condition: true }', family='other')
    last = repo.add('deleted', 'text')
    repo.delete(last)
    yield repo
    repo.close()


def test_backup_captures_live_wal_and_restore_preserves_all_fields(repository, tmp_path):
    assert Path(repository._db_path + '-wal').exists()
    backup = tmp_path / 'backup.db'
    backup_database(repository._db_path, backup)
    expected = repository.search()
    repository.add('after_backup', 'not included')
    target = tmp_path / 'migrated.db'
    restore_database(backup, target)
    restored = RuleRepository(target)
    try:
        assert restored.search() == expected
        assert restored.search(q='needle')[0]['family'] == '雪'
        assert restored.add('new', 'text') == 4  # Deleted IDs remain reserved.
    finally:
        restored.close()
    reopened = RuleRepository(target)
    try:
        assert len(reopened.search()) == 3
    finally:
        reopened.close()


def test_export_preserves_source_and_metadata_with_safe_paths(repository, tmp_path):
    repository.add('../../bad:name', 'rule bad { condition: "雪" == "雪" }', family='../')
    target = tmp_path / 'rules.zip'
    export_database(repository._db_path, target)
    with zipfile.ZipFile(target) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        assert manifest['version'] == 1
        assert manifest['format'] == 'yaraxgui-rule-export'
        for entry in manifest['rules']:
            original = repository.get(entry['id'])
            assert entry.pop('file') == f'rules/{entry["id"]}.yar'
            assert archive.read(f'rules/{entry["id"]}.yar').decode('utf-8') == original.pop('rule_text')
            assert entry == original
        assert len(archive.namelist()) == 4


def test_never_overwrites_output_or_missing_source(repository, tmp_path):
    target = tmp_path / 'keep.db'
    target.write_bytes(b'keep')
    for operation in (backup_database, export_database, restore_database):
        with pytest.raises(FileExistsError):
            operation(repository._db_path, target)
        assert target.read_bytes() == b'keep'
    missing = tmp_path / 'missing.db'
    with pytest.raises(sqlite3.OperationalError):
        backup_database(missing, tmp_path / 'new.db')
    assert not missing.exists()
    assert not (tmp_path / 'new.db').exists()


def test_restore_failure_keeps_existing_repository(repository, tmp_path):
    corrupt = tmp_path / 'bad.db'
    corrupt.write_bytes(b'not sqlite')
    before = repository.search()
    with pytest.raises(sqlite3.DatabaseError):
        restore_database(corrupt, repository._db_path, replace=True)
    assert repository.search() == before
    unknown = tmp_path / 'unknown.db'
    with sqlite3.connect(unknown) as db:
        db.execute('CREATE TABLE rules(id INTEGER)')
    with pytest.raises(ValueError, match='schema'):
        restore_database(unknown, repository._db_path, replace=True)
    assert repository.search() == before


def test_restore_rebuilds_schema_instead_of_installing_source_triggers(repository, tmp_path):
    backup = tmp_path / 'backup.db'
    backup_database(repository._db_path, backup)
    with sqlite3.connect(backup) as db:
        db.execute("CREATE TRIGGER sabotage AFTER INSERT ON rules BEGIN DELETE FROM rules; END")
    target = tmp_path / 'target.db'
    restore_database(backup, target)
    restored = RuleRepository(target)
    try:
        restored.add('new', 'text')
        assert len(restored.search()) == 3
        assert not restored._conn.execute("SELECT 1 FROM sqlite_schema WHERE name='sabotage'").fetchall()
    finally:
        restored.close()


def test_replace_existing_database_and_empty_repository(repository, tmp_path):
    empty = RuleRepository(tmp_path / 'empty.db')
    empty.close()
    restore_database(tmp_path / 'empty.db', repository._db_path, replace=True)
    assert repository.stats()['total_rules'] == 0
    assert repository.search(q='needle') == []


def test_binary_cli_round_trip(repository, tmp_path):
    base = [sys.executable, '-m', 'api.repository_transfer']
    result = subprocess.run(base + ['backup', '-', '--database', repository._db_path],
                            check=True, capture_output=True)
    assert result.stdout.startswith(b'SQLite format 3\x00')
    target = tmp_path / 'target.db'
    subprocess.run(base + ['restore', '-', '--database', str(target)],
                   input=result.stdout, check=True, capture_output=True)
    restored = RuleRepository(target)
    try:
        assert restored.search() == repository.search()
    finally:
        restored.close()


def test_compose_storage_selection():
    windows, linux = compose_command('windows'), compose_command('linux')
    assert any(arg.endswith('compose.windows.yaml') for arg in windows)
    assert not any(arg.endswith('compose.windows.yaml') for arg in linux)
    assert '--project-directory' in windows


def test_host_output_is_binary_and_no_partial_backup_on_failure(tmp_path, monkeypatch):
    def success(command, **kwargs):
        assert command[-4:] == ['-m', 'api.repository_transfer', 'backup', '-']
        assert '-T' in command
        kwargs['stdout'].write(b'\x00\xff\r\n')
    monkeypatch.setattr(subprocess, 'run', success)
    target = tmp_path / 'backups' / 'rules.db'
    transfer('backup', target, storage='windows')
    assert target.read_bytes() == b'\x00\xff\r\n'

    def failure(command, **kwargs):
        kwargs['stdout'].write(b'incomplete')
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(subprocess, 'run', failure)
    failed = tmp_path / 'failed.db'
    with pytest.raises(subprocess.CalledProcessError):
        transfer('backup', failed, storage='linux')
    assert not failed.exists()
    assert target.read_bytes() == b'\x00\xff\r\n'


@pytest.mark.parametrize('state', ['running', 'restarting', 'paused', 'unknown'])
def test_host_restore_refuses_running_api(tmp_path, monkeypatch, state):
    source = tmp_path / 'rules.db'
    source.write_bytes(b'backup')
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps([{'State': state}]))
    monkeypatch.setattr(subprocess, 'run', run)
    with pytest.raises(ValueError, match='Stop the destination API'):
        transfer('restore', source, storage='windows', replace=True)
    assert len(calls) == 1


@pytest.mark.parametrize('status', ['', '[]', '{"State":"exited"}\n', '[{"State":"created"}]'])
def test_host_restore_streams_file_to_stopped_destination(tmp_path, monkeypatch, status):
    source = tmp_path / 'backup with spaces.db'
    source.write_bytes(b'\x00\xff\r\n')
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if 'ps' in command:
            return subprocess.CompletedProcess(command, 0, stdout=status)
        assert kwargs['stdin'].read() == source.read_bytes()
        assert '--replace' in command
        assert ['run', '--rm', '-T', '--no-deps'] == command[command.index('run'):command.index('run') + 4]
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(subprocess, 'run', run)
    transfer('restore', source, storage='windows', replace=True)
    assert len(calls) == 2


def test_interrupted_sqlite_restore_rolls_back_existing_data(repository, tmp_path, monkeypatch):
    import api.repository_transfer as toolkit
    other = RuleRepository(tmp_path / 'other.db')
    other.add('large', 'x' * 200000)
    other.close()
    before = repository.search()
    original = toolkit.copy_database
    calls = 0
    def interrupted(source, target):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(source, target)
        def stop(*args):
            raise RuntimeError('interrupted during restore')
        source.backup(target, pages=1, progress=stop)
    monkeypatch.setattr(toolkit, 'copy_database', interrupted)
    with pytest.raises(RuntimeError, match='interrupted'):
        restore_database(tmp_path / 'other.db', repository._db_path, replace=True)
    assert repository.search() == before
    assert repository.search(q='needle')


def test_failed_zip_export_removes_partial_file(repository, tmp_path, monkeypatch):
    def disk_full(*args, **kwargs):
        raise OSError('disk full')
    monkeypatch.setattr(zipfile.ZipFile, 'writestr', disk_full)
    target = tmp_path / 'failed.zip'
    with pytest.raises(OSError, match='disk full'):
        export_database(repository._db_path, target)
    assert not target.exists()


def test_failed_snapshot_removes_partial_file(repository, tmp_path, monkeypatch):
    import api.repository_transfer as toolkit
    def fail(*args, **kwargs):
        raise OSError('disk full')
    monkeypatch.setattr(toolkit, 'copy_database', fail)
    target = tmp_path / 'failed.db'
    with pytest.raises(OSError, match='disk full'):
        backup_database(repository._db_path, target)
    assert not target.exists()
    assert repository.stats()['total_rules'] == 2


@pytest.mark.parametrize('storage,launcher', [
    ('linux', './scripts/compose.sh'), ('windows', r'.\scripts\compose.bat'),
])
def test_missing_container_module_gives_rebuild_steps(tmp_path, monkeypatch, storage, launcher):
    def stale_image(command, **kwargs):
        assert kwargs['stderr'] == subprocess.PIPE
        raise subprocess.CalledProcessError(1, command,
            stderr=b'/usr/local/bin/python: No module named api.repository_transfer\n')
    monkeypatch.setattr(subprocess, 'run', stale_image)
    target = tmp_path / 'backup.db'
    with pytest.raises(ValueError, match='API container image is missing') as error:
        transfer('backup', target, storage=storage)
    assert launcher + ' up -d --build --force-recreate' in str(error.value)
    assert not target.exists()
