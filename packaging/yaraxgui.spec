# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules, copy_metadata

block_cipher = None

# Resolve resources relative to this spec, including builds from another cwd.
current_dir = Path(SPECPATH).resolve().parent
editor_datas, editor_binaries, editor_hiddenimports = collect_all('yarax_editor')
editor_datas += copy_metadata('yara-x')

# pycryptodome is imported lazily inside transform_ops/symmetric.py, so
# PyInstaller's static analysis doesn't see it. Pull in every submodule,
# native binary and data file so AES/RC4/ChaCha20 work in the frozen exe.
crypto_datas, crypto_binaries, crypto_hiddenimports = collect_all('Crypto')
# Drop pycryptodome's bundled test vectors — they add ~30 MB of dead weight.
crypto_datas = [d for d in crypto_datas if 'SelfTest' not in d[0].replace('\\', '/')]
crypto_hiddenimports = [m for m in crypto_hiddenimports if not m.startswith('Crypto.SelfTest')]

# Auto-discover every hex_editor transform plugin module so new ones get
# picked up by the build without having to edit this spec every time.
transform_ops_hiddenimports = collect_submodules('hex_editor.transform_ops')

# lz4 and zstandard are imported lazily in compression.py
lz4_datas, lz4_binaries, lz4_hiddenimports = collect_all('lz4')
zstd_datas, zstd_binaries, zstd_hiddenimports = collect_all('zstandard')

# capstone is imported lazily in disasm_widget.py and has a native DLL
cap_datas, cap_binaries, cap_hiddenimports = collect_all('capstone')
# Drop test data to save space
cap_datas = [d for d in cap_datas if 'test' not in d[0].lower()]

# keyring — OS credential backend discovered at runtime
keyring_hiddenimports = collect_submodules('keyring')

# mwdblib — only core API needed, skip CLI (needs beautifultable)
mwdblib_hiddenimports = [
    'mwdblib', 'mwdblib.api', 'mwdblib.blob', 'mwdblib.comment',
    'mwdblib.config', 'mwdblib.exc', 'mwdblib.file', 'mwdblib.karton',
    'mwdblib.object', 'mwdblib.share', 'mwdblib.util',
]

# pydantic — used by FastAPI plugin endpoints and api/models.py
pydantic_hiddenimports = collect_submodules('pydantic')

# FastAPI/uvicorn/starlette — used by API server and plugin endpoints
fastapi_hiddenimports = collect_submodules('fastapi')
uvicorn_hiddenimports = collect_submodules('uvicorn')
starlette_hiddenimports = collect_submodules('starlette')

a = Analysis(
    [str(current_dir / 'mainwindow.py')],
    pathex=[str(current_dir)],
    binaries=crypto_binaries + lz4_binaries + zstd_binaries + cap_binaries + editor_binaries,
    datas=[
        # Bundle theme defaults, never user settings or local databases.
        (str(current_dir / 'config/themes.json'), 'config'),
        (str(current_dir / 'docs'), 'docs'),
        # Include assets folder (for runtime icon loading)
        (str(current_dir / 'assets'), 'assets'),
        # Include plugins directory
        (str(current_dir / 'plugins'), 'plugins'),
    ] + crypto_datas + lz4_datas + zstd_datas + cap_datas + editor_datas,
    hiddenimports=[
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        # YARA
        'yara_x',
        'hex_editor.analysis_worker',
        'hex_editor.analysis_limits',
        'hex_editor.thread_lifecycle',
        'hex_editor.analysis_jobs',
        'hex_editor.analysis_controller',
        'hex_editor.analysis_results',
        'capstone',
        # Plugin framework + built-in plugins (loaded dynamically)
        'plugins',
        'plugins.__init__',
        'plugins.base',
        'plugins.rule_repository',
        'plugins.mwdb_retrohunt',
        # API modules (used by plugins and rule_repo_dock)
        'api',
        'api.__init__',
        'api.models',
        'api.rule_repo',
        'api.scan_manager',
        'api.yaraxgui_api',
        # Hex editor submodules (many imported lazily)
        'hex_editor',
        'hex_editor.__init__',
        'hex_editor.binary_diff',
        'hex_editor.binary_diff_window',
        'hex_editor.clipboard_exporter',
        'hex_editor.data_inspector',
        'hex_editor.disasm_widget',
        'hex_editor.edit_controller',
        'hex_editor.edit_log_widget',
        'hex_editor.elf_parser',
        'hex_editor.entropy_widget',
        'hex_editor.format_viewer',
        'hex_editor.goto_dialog',
        'hex_editor.hex_data_buffer',
        'hex_editor.hex_editor_window',
        'hex_editor.hex_layout',
        'hex_editor.hex_painter',
        'hex_editor.hex_search',
        'hex_editor.hex_widget',
        'hex_editor.pe_parser',
        'hex_editor.selection_model',
        'hex_editor.string_extractor',
        'hex_editor.transform_dialog',
        'hex_editor.transform_log',
        'hex_editor.transforms',
        'hex_editor.xor_scanner',
    ] + collect_submodules('yaraxgui', filter=lambda name: name != 'yaraxgui.__main__')
      + editor_hiddenimports + crypto_hiddenimports + transform_ops_hiddenimports
      + lz4_hiddenimports + zstd_hiddenimports + cap_hiddenimports
      + keyring_hiddenimports + mwdblib_hiddenimports
      + pydantic_hiddenimports + fastapi_hiddenimports
      + uvicorn_hiddenimports + starlette_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['Crypto.SelfTest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='YaraXGUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to True if you want console for debugging
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(current_dir / 'assets/YaraXGUI.ico'),
)
