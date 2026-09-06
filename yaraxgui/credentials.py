"""Secure credential storage using the OS keyring.

Uses Windows Credential Manager (or macOS Keychain / Linux Secret Service)
via the ``keyring`` library. If unavailable, newly saved secrets remain in
memory for this session only. Legacy settings are read for migration.

Service name: ``YaraXGUI`` — all credentials are stored under this namespace.
"""

from __future__ import annotations

SERVICE = "YaraXGUI"
_session_secrets: dict[str, str] = {}

_keyring_available = False
try:
    import keyring as _kr
    _keyring_available = True
except ImportError:
    _kr = None


def is_available() -> bool:
    """Return True if the OS keyring backend is usable."""
    if not _keyring_available:
        return False
    try:
        return _kr.get_keyring().priority > 0
    except Exception:
        return False


def store(key: str, secret: str):
    """Store a secret in the OS keyring."""
    if _keyring_available:
        _kr.set_password(SERVICE, key, secret)
    else:
        raise RuntimeError("keyring not installed — pip install keyring")


def retrieve(key: str) -> str:
    """Retrieve a secret from the OS keyring. Returns '' if not found."""
    if _keyring_available:
        val = _kr.get_password(SERVICE, key)
        return val or ""
    return ""


def delete(key: str):
    """Delete a secret from the OS keyring."""
    if _keyring_available:
        try:
            _kr.delete_password(SERVICE, key)
        except Exception:
            pass


# Well-known credential keys
MWDB_TOKEN = "mwdb_token"
MWDB_PASSWORD = "mwdb_password"
API_SERVER_KEY = "api_server_key"


def load_setting_secret(key: str, legacy_key: str, get_setting) -> str:
    """Read the same credential for Settings and clients, including old installs."""
    if key in _session_secrets:
        return _session_secrets[key]
    # Remember an explicit fallback after a failed write. Otherwise a stale
    # keyring entry could mask a replacement saved while the keyring was locked.
    if get_setting(f'{key}_storage', '') not in ('settings', 'session'):
        try:
            value = retrieve(key)
            if value:
                return value
        except Exception:
            pass
    return get_setting(legacy_key, '') or ''


def save_setting_secret(key: str, legacy_key: str, secret: str, save_setting) -> None:
    """Prefer the keyring; never write new plaintext secrets into settings."""
    try:
        store(key, secret)
    except Exception:
        _session_secrets[key] = secret
        save_setting(legacy_key, '')
        save_setting(f'{key}_storage', 'session')
    else:
        _session_secrets.pop(key, None)
        save_setting(legacy_key, '')
        save_setting(f'{key}_storage', 'keyring')


def api_server_key(get_setting) -> str:
    """Current YaraXGUI API key, shared by all GUI API clients."""
    return load_setting_secret(API_SERVER_KEY, 'repo_api_key', get_setting)
