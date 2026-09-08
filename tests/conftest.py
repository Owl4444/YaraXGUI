import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if sys.platform == "win32" and os.environ["QT_QPA_PLATFORM"] == "offscreen":
    # Qt's offscreen FreeType backend does not discover Windows system fonts.
    os.environ.setdefault("QT_QPA_FONTDIR", os.path.join(os.environ["WINDIR"], "Fonts"))
os.environ["YARAXGUI_DEV_MODE"] = "1"
os.environ["YARAXGUI_RATE_LIMIT"] = "100000"

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def isolated_user_state(tmp_path, monkeypatch):
    # Recovery and desktop databases must stay inside each test's directory,
    # including in child processes on Windows (which ignores XDG_DATA_HOME).
    monkeypatch.setenv('YARAXGUI_RECOVERY_DIR', str(tmp_path / 'recovery'))
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
    monkeypatch.setenv('APPDATA', str(tmp_path / 'roaming'))
    monkeypatch.setattr('yaraxgui.credentials._session_secrets', {})
