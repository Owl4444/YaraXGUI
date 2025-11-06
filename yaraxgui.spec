# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

block_cipher = None

# Get the current directory
current_dir = Path.cwd()

a = Analysis(
    ['mainwindow.py'],
    pathex=[str(current_dir)],
    binaries=[],
    datas=[
        # Include config files
        ('config', 'config'),
        # Include assets folder (for runtime icon loading)
        ('assets', 'assets'),
        # Include form.ui file if it exists
        ('form.ui', '.'),
    ],
    hiddenimports=[
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'yaraast',
        'yaraast.parser',
        'yaraast.parser.better_parser',
        'yaraast.ast',
        'yaraast.ast.base',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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