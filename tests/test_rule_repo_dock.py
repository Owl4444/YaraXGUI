from unittest.mock import Mock

import pytest

import yaraxgui.repository.local_store as local_rule_store
from yaraxgui.repository.dock import RuleRepoDock


@pytest.fixture
def dock(app, tmp_path, monkeypatch):
    monkeypatch.setattr(local_rule_store, "prepare_local_database", lambda: tmp_path / "rules.db")
    widget = RuleRepoDock()
    yield widget
    if widget._local_repo:
        widget._local_repo.close()
    widget.deleteLater()


def test_dock_reopens_saved_rules(dock):
    dock._repo_add(name="saved", rule_text="text")
    dock._on_search()
    assert "1 rules" in dock._local_status.text()
    assert str(dock._local_repo._db_path) in dock._local_status.text()
    reopened = RuleRepoDock()
    try:
        assert [r["name"] for r in reopened._rules] == ["saved"]
    finally:
        reopened._local_repo.close()
        reopened.deleteLater()


def test_pagination_exposes_every_rule(dock):
    for i in range(205):
        dock._repo_add(name=f"rule_{i}", rule_text="text")
    dock._on_search()
    first_page = {r["id"] for r in dock._rules}
    assert len(first_page) == 200
    assert dock._next_btn.isEnabled()
    dock._next_btn.click()
    assert len(dock._rules) == 5
    assert not first_page.intersection(r["id"] for r in dock._rules)
    assert not dock._next_btn.isEnabled()
    dock._previous_btn.click()
    assert {r["id"] for r in dock._rules} == first_page


def test_changed_filter_restarts_pagination(dock):
    for i in range(205):
        dock._repo_add(name=f"rule_{i}", rule_text="text", family="one" if i == 0 else "many")
    dock._on_search()
    dock._family_combo.setCurrentText("one")
    dock._next_btn.click()
    assert [r["name"] for r in dock._rules] == ["rule_0"]
    assert dock._offset == 0


def test_switching_mode_clears_filters_and_disables_disconnected_actions(dock):
    dock._repo_add(name="local", rule_text="text", family="local_family")
    dock._on_search()
    dock._family_combo.setCurrentIndex(1)
    dock._search_input.setText("local")
    dock._mode_combo.setCurrentIndex(1)
    assert not dock._rules
    assert not dock._upload_btn.isEnabled()
    assert dock._family_combo.count() == 1
    dock._family_combo.addItem("remote_family")
    dock._family_combo.setCurrentIndex(1)
    dock._search_input.setText("remote")
    dock._mode_combo.setCurrentIndex(0)
    assert [r["name"] for r in dock._rules] == ["local"]
    assert dock._upload_btn.isEnabled()


def test_failed_local_initialization_never_falls_back_to_remote(app, monkeypatch):
    monkeypatch.setattr(local_rule_store, "prepare_local_database", Mock(side_effect=OSError("read only")))
    widget = RuleRepoDock()
    try:
        widget._api = Mock(side_effect=AssertionError("unexpected remote access"))
        with pytest.raises(RuntimeError, match="Local database unavailable"):
            widget._repo_add(name="name", rule_text="text")
        assert not widget._upload_btn.isEnabled()
        assert "read only" in widget._local_status.text()
        widget._api.assert_not_called()
    finally:
        widget.deleteLater()


def test_failed_search_clears_stale_selection(dock):
    dock._repo_add(name="sample", rule_text="text")
    dock._on_search()
    dock._table.setCurrentCell(0, 0)
    assert dock._delete_btn.isEnabled()
    dock._search_input.setText('"')
    dock._on_search()
    assert not dock._rules
    assert not dock._delete_btn.isEnabled()


def test_failed_reconnection_clears_old_server(dock, monkeypatch):
    dock._mode_combo.setCurrentIndex(1)
    dock._server_url = "https://old.example"
    dock._server_input.setText("https://new.example")
    monkeypatch.setattr(dock, "_repo_stats", Mock(side_effect=RuntimeError("offline")))
    dock._on_connect()
    assert not dock._server_url
    assert not dock._upload_btn.isEnabled()
    assert "Connection failed" in dock._status.text()


def test_missing_local_mutation_is_an_error(dock):
    dock._repo_add(name="sample", rule_text="text")
    with pytest.raises(RuntimeError, match="Rule not found"):
        dock._repo_update(999, name="missing")
    with pytest.raises(RuntimeError, match="Rule not found"):
        dock._repo_delete(999)


def test_remote_requests_use_current_settings_key_without_tab_input(dock, monkeypatch):
    from io import BytesIO
    import yaraxgui.credentials as credential_store
    import urllib.request

    settings = {'repo_api_key': 'legacy-test-key'}
    secret = {'value': 'settings-test-key'}
    monkeypatch.setattr(credential_store, 'retrieve', lambda key: secret['value'])
    dock._get_setting = settings.get
    dock._server_url = 'https://example.invalid'
    assert not hasattr(dock, '_key_input')
    requests = []

    def request(req, get_setting, timeout):
        requests.append(req)
        return BytesIO(b'{}')
    monkeypatch.setattr('yaraxgui.network.api_urlopen', request)
    for value in ('settings-test-key', 'rotated-test-key', ''):
        secret['value'] = value
        settings['repo_api_key'] = ''  # Settings clears the legacy key on save.
        dock._api('GET', '/repo/stats')
        assert requests[-1].get_header('X-api-key', '') == value


def test_connect_persists_url_without_copying_credentials(dock, monkeypatch):
    saved = {}
    dock._save_setting = saved.__setitem__
    dock.set_server('https://example.invalid')
    monkeypatch.setattr(dock, '_repo_stats', lambda: {})
    monkeypatch.setattr(dock, '_repo_families', lambda: [])
    monkeypatch.setattr(dock, '_on_search', lambda: None)
    dock._on_connect()
    assert saved == {'repo_server_url': 'https://example.invalid'}


def test_changing_settings_server_never_sends_new_key_to_old_server(dock, monkeypatch):
    request = Mock()
    monkeypatch.setattr('yaraxgui.network.api_urlopen', request)
    dock._server_url = 'https://old.example.invalid'
    dock._get_setting = {'repo_server_url':'https://new.example.invalid', 'repo_api_key':'new-key'}.get
    with pytest.raises(RuntimeError, match='Reconnect'):
        dock._api('GET', '/repo/stats')
    request.assert_not_called()


def test_connection_failure_shows_copyable_docker_diagnostic(dock, monkeypatch):
    from urllib.error import URLError
    from PySide6.QtCore import Qt
    import yaraxgui.network as network

    dock._mode_combo.setCurrentIndex(1)
    dock._server_input.setText('https://example.test:7777')
    opener = Mock(side_effect=URLError(ConnectionRefusedError(10061, 'refused')))
    monkeypatch.setattr(network, 'api_urlopen', opener)
    dock._on_connect()
    assert 'Connection refused' in dock._status.text()
    assert 'use https://example.test (port 443)' in dock._status.text()
    assert dock._status.wordWrap()
    assert dock._status.textFormat() == Qt.TextFormat.PlainText
    assert dock._status.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByMouse
    assert not dock._server_url
    assert not dock._upload_btn.isEnabled()
    opener.assert_called_once()  # Never retry over HTTP or with verification disabled.


def test_http_auth_error_is_not_reported_as_network_failure(dock, monkeypatch):
    from io import BytesIO
    from urllib.error import HTTPError
    import yaraxgui.network as network

    dock._server_url = 'https://example.test'
    monkeypatch.setattr(network, 'api_urlopen', Mock(side_effect=HTTPError(
        dock._server_url, 403, 'Forbidden', {}, BytesIO(b'{"detail":"Invalid API key"}'))))
    with pytest.raises(RuntimeError, match='HTTP 403: Invalid API key'):
        dock._api('GET', '/repo/stats')
