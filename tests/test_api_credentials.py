from unittest.mock import Mock

import pytest

import yaraxgui.credentials as credentials


@pytest.fixture
def secrets(monkeypatch):
    values = {}
    monkeypatch.setattr(credentials, 'retrieve', lambda key: values.get(key, ''))
    monkeypatch.setattr(credentials, 'store', lambda key, value: values.__setitem__(key, value))
    return values


def test_keyring_settings_and_legacy_credentials_use_one_resolver(secrets):
    settings = {'repo_api_key': 'legacy-test-key'}
    assert credentials.api_server_key(settings.get) == 'legacy-test-key'
    secrets[credentials.API_SERVER_KEY] = 'keyring-test-key'
    assert credentials.api_server_key(settings.get) == 'keyring-test-key'


def test_save_replace_and_clear_remove_legacy_copy(secrets):
    settings = {'repo_api_key': 'old-test-key'}
    for value in ('first-test-key', 'replacement-test-key', ''):
        credentials.save_setting_secret(credentials.API_SERVER_KEY, 'repo_api_key',
                                        value, settings.__setitem__)
        assert settings['repo_api_key'] == ''
        assert secrets[credentials.API_SERVER_KEY] == value
        assert credentials.api_server_key(settings.get) == value


def test_failed_keyring_write_does_not_revive_old_key(secrets, monkeypatch):
    secrets[credentials.API_SERVER_KEY] = 'stale-test-key'
    settings = {}
    monkeypatch.setattr(credentials, 'store', Mock(side_effect=RuntimeError('locked')))
    for value in ('replacement-test-key', ''):
        credentials.save_setting_secret(credentials.API_SERVER_KEY, 'repo_api_key',
                                        value, settings.__setitem__)
        assert credentials.api_server_key(settings.get) == value


def test_unavailable_keyring_loads_legacy_setting(monkeypatch):
    monkeypatch.setattr(credentials, 'retrieve', Mock(side_effect=RuntimeError('no backend')))
    assert credentials.api_server_key({'repo_api_key': 'legacy-test-key'}.get) == 'legacy-test-key'
    assert credentials.api_server_key({}.get) == ''


def test_keyring_recovery_migrates_fallback_and_clears_plaintext(secrets):
    settings = {'repo_api_key': 'fallback-test-key', 'api_server_key_storage': 'settings'}
    credentials.save_setting_secret(credentials.API_SERVER_KEY, 'repo_api_key',
                                    credentials.api_server_key(settings.get), settings.__setitem__)
    assert settings['repo_api_key'] == ''
    assert settings['api_server_key_storage'] == 'keyring'
    assert credentials.api_server_key(settings.get) == 'fallback-test-key'


def test_failed_secret_write_does_not_revive_stale_key_after_restart(secrets, monkeypatch):
    secrets[credentials.API_SERVER_KEY] = 'stale-key'
    settings = {}
    monkeypatch.setattr(credentials, 'store', Mock(side_effect=RuntimeError('locked')))
    credentials.save_setting_secret(credentials.API_SERVER_KEY, 'repo_api_key',
                                    'new-key', settings.__setitem__)
    assert credentials.api_server_key(settings.get) == 'new-key'
    assert 'new-key' not in str(settings)
    credentials._session_secrets.clear()  # Application restart
    assert credentials.api_server_key(settings.get) == ''
