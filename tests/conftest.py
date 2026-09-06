import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["YARAXGUI_DEV_MODE"] = "1"
os.environ["YARAXGUI_RATE_LIMIT"] = "100000"

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def isolated_recovery(tmp_path, monkeypatch):
    # GUI smoke tests must never read or overwrite a real user's recovery data.
    monkeypatch.setenv('YARAXGUI_RECOVERY_DIR', str(tmp_path / 'recovery'))
    monkeypatch.setattr('yaraxgui.credentials._session_secrets', {})
