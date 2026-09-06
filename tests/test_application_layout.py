"""Integration checks for source, bundle, and headless package boundaries."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from yaraxgui.paths import resource_root


@pytest.mark.parametrize("frozen", [False, True])
def test_resources_and_settings_from_another_directory(tmp_path, monkeypatch, frozen):
    from yaraxgui.app import MainWindow
    from yaraxgui.ui.help import documentation_pages
    from yaraxgui.ui.themes import ThemeManager

    root = Path(__file__).resolve().parents[1]
    if frozen:
        bundle = tmp_path / "bundle"
        for folder in ("assets", "docs", "config", "plugins"):
            # Copy only shared resources, never a developer's local settings.
            (bundle / folder).mkdir(parents=True)
        for filename in ("config/themes.json", "assets/YaraXGUI.ico",
                         "plugins/rule_repository.py"):
            shutil.copyfile(root / filename, bundle / filename)
        for page in (root / "docs").glob("*.md"):
            shutil.copyfile(page, bundle / "docs" / page.name)
        root = bundle
        monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "preferences"))
    monkeypatch.chdir(tmp_path)

    assert resource_root() == root
    assert (root / "assets/YaraXGUI.ico").is_file()
    assert (root / "plugins/rule_repository.py").is_file()
    assert {"Light", "Dark"} <= ThemeManager().get_available_themes().keys()
    assert any(title == "User Guide" and body for title, _, body in documentation_pages())
    expected = (tmp_path / "preferences/YaraXGUI/settings.json" if frozen
                else root / "config/settings.json")
    assert MainWindow._settings_path(None) == expected


def test_api_and_plugins_run_without_desktop_dependencies(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(root),
               YARAXGUI_REPO_DB=str(tmp_path / "rules.db"),
               YARAXGUI_UPLOAD_DIR=str(tmp_path / "uploads"),
               YARAXGUI_ALLOWED_ROOTS=str(tmp_path), YARAXGUI_API_KEY="")
    result = subprocess.run([sys.executable, "-c", """
import importlib.abc
import sys

class NoDesktopDependencies(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'PySide6', 'keyring', 'PyInstaller'}:
            raise AssertionError('Headless API imported ' + fullname)

sys.meta_path.insert(0, NoDesktopDependencies())
from fastapi.testclient import TestClient
from api.yaraxgui_api import app
from plugins.base import PLUGIN_REGISTRY
from yaraxgui.scanning.scanner import YaraScanner

with TestClient(app, client=('127.0.0.1', 50000), base_url='http://localhost') as client:
    assert client.get('/health').status_code == 200
assert {'rule_repository', 'mwdb'} <= set(PLUGIN_REGISTRY)
assert YaraScanner().compile_rules('rule smoke { condition: true }').scan(b'x').matching_rules
print('headless-ok')
"""], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "headless-ok" in result.stdout
