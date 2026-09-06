import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import yaraxgui.repository.local_store as local_rule_store
from api.rule_repo import RuleRepository


@pytest.fixture
def repo(tmp_path):
    repository = RuleRepository(tmp_path / "nested/rules.db")
    yield repository
    repository.close()


def test_changes_persist_and_fts_tracks_updates(repo):
    rid = repo.add("sample", "rule sample { condition: true }", family="old")
    assert repo.update(rid, family="new", description="needle")
    other = RuleRepository(repo._db_path)
    try:
        assert other.get(rid)["family"] == "new"
        assert [r["id"] for r in other.search(q="needle", family="new")] == [rid]
        assert other.search(q="old") == []
        assert repo.delete(rid)
        assert other.get(rid) is None
        assert other.search(q="needle") == []
    finally:
        other.close()


@pytest.mark.parametrize("field,value", [
    ("family", "family"), ("tags", "tag"),
    ("author", "author"), ("source", "source"),
])
def test_full_text_search_with_metadata_filters(repo, field, value):
    rid = repo.add("needle", "rule needle { condition: true }", **{field: value})
    assert [r["id"] for r in repo.search(q="needle", **{field: value})] == [rid]


def test_missing_mutations_do_not_report_prior_changes(repo):
    rid = repo.add("exists", "text")
    assert not repo.update(rid + 1, author="someone")
    assert not repo.delete(rid + 1)
    assert repo.delete(rid)
    assert not repo.delete(rid)


def test_duplicate_write_rolls_back_and_releases_lock(repo):
    repo.add("exists", "text")
    with pytest.raises(sqlite3.IntegrityError):
        repo.add("exists", "duplicate")
    assert not repo._conn.in_transaction
    other = RuleRepository(repo._db_path)
    try:
        other.add("different", "text")
    finally:
        other.close()


def test_restart_from_different_working_directory(tmp_path):
    env = dict(os.environ, XDG_DATA_HOME=str(tmp_path / "data"),
               PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    setup = "from yaraxgui.repository.local_store import prepare_local_database; from api.rule_repo import RuleRepository; r = RuleRepository(prepare_local_database()); "
    subprocess.run([sys.executable, "-c", setup + "r.add('persistent', 'text')"],
                   cwd=tmp_path, env=env, check=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    result = subprocess.run([sys.executable, "-c", setup + "print(r.search()[0]['name'])"],
                            cwd=elsewhere, env=env, check=True, capture_output=True, text=True)
    assert result.stdout.strip() == "persistent"


@pytest.mark.parametrize("platform,env_name,folder", [
    ("linux", "XDG_DATA_HOME", "data"),
    ("win32", "LOCALAPPDATA", "local"),
    ("darwin", None, "Library/Application Support"),
])
def test_platform_location_is_independent_of_bundle(tmp_path, monkeypatch, platform, env_name, folder):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    if env_name:
        monkeypatch.setenv(env_name, str(tmp_path / folder))
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(local_rule_store, "resource_root", lambda: tmp_path / "_MEI123")
    assert local_rule_store.local_database_path() == tmp_path / folder / "YaraXGUI/local_rules.db"


def test_migration_includes_wal_and_never_overwrites(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(local_rule_store, "resource_root", lambda: tmp_path / "old")
    legacy = RuleRepository(tmp_path / "old/config/local_rules.db")
    try:
        rid = legacy.add("legacy", "text")
        assert Path(legacy._db_path + "-wal").exists()
        path = local_rule_store.prepare_local_database()
        migrated = RuleRepository(path)
        try:
            assert migrated.get(rid)["name"] == "legacy"
            migrated.delete(rid)
            local_rule_store.prepare_local_database()
            assert migrated.search() == []
            assert legacy.get(rid)["name"] == "legacy"
        finally:
            migrated.close()
    finally:
        legacy.close()


def test_failed_migration_does_not_publish_empty_database(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(local_rule_store, "resource_root", lambda: tmp_path / "old")
    legacy = tmp_path / "old/config/local_rules.db"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("invalid database")
    with pytest.raises(sqlite3.DatabaseError):
        local_rule_store.prepare_local_database()
    assert not local_rule_store.local_database_path().exists()
    assert legacy.read_text() == "invalid database"


def test_packaged_restart_uses_saved_copy_after_bundle_disappears(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "install/YaraXGUI.exe"))
    monkeypatch.setattr(local_rule_store, "resource_root", lambda: tmp_path / "_MEI_first")
    legacy = RuleRepository(tmp_path / "install/config/local_rules.db")
    legacy.add("saved", "text")
    legacy.close()
    first_path = local_rule_store.prepare_local_database()
    monkeypatch.setattr(local_rule_store, "resource_root", lambda: tmp_path / "_MEI_second")
    second_path = local_rule_store.prepare_local_database()
    assert first_path == second_path
    repo = RuleRepository(second_path)
    try:
        assert repo.search()[0]["name"] == "saved"
    finally:
        repo.close()
