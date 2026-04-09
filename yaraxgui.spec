# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

# Get the current directory
current_dir = Path.cwd()

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

a = Analysis(
    ['mainwindow.py'],
    pathex=[str(current_dir)],
    binaries=crypto_binaries,
    datas=[
        # Include config files
        ('config', 'config'),
        # Include assets folder (for runtime icon loading)
        ('assets', 'assets'),
        # Include form.ui file if it exists
        ('form.ui', '.'),
    ] + crypto_datas,
    hiddenimports=[
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'yaraast',
        'yaraast.parser',
        'yaraast.parser.better_parser',
        'yaraast.ast',
        'yaraast.ast.base',
    ] + crypto_hiddenimports + transform_ops_hiddenimports,
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
    icon='./assets/YaraXGUI.ico',
)