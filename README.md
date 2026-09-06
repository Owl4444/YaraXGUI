# YaraXGUI

Write YARA rules, scan files with YARA-X, and inspect matches in a hex editor.
Use it as a desktop app, or connect to your own server to share a rule repository.

**[Cheatsheet](docs/CHEATSHEET.md)** · [User guide](docs/USER_GUIDE.md) ·
[Server setup by LAN IP](docs/API_SECURITY.md#lan-https-by-ip-address-no-domain-needed) ·
[Backups and migration](docs/REPOSITORY_BACKUPS.md)

## What you can do

- Edit rules with suggestions, diagnostics, formatting, and multiple tabs.
- Scan files and inspect matching bytes, strings, entropy, disassembly, and CFGs.
- Apply transform recipes, including decoding, decryption, and decompression.
- Save rules in a persistent local or remote repository, review edits, and export backups.
- Browse MWDB and run retrohunts through the desktop or headless API.

## Run the desktop app

Requires **64-bit Python 3.12+**. Windows examples use Python 3.13.
Clone the project once, or open your existing checkout:

```sh
git clone https://github.com/Owl4444/YaraXGUI.git
cd YaraXGUI
```

Run commands from the folder containing this README and `requirements.txt`.

**Windows — PowerShell**

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m yaraxgui
```

**Linux / macOS**

```sh
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python -m yaraxgui
```

For later launches, run only the last command. To build a Windows executable:

```powershell
.\compile_to_exe.bat py -3.13
```

The result is `dist/YaraXGUI.exe`. See [build troubleshooting](docs/DEVELOPMENT.md#windows-build-troubleshooting).

## Your first scan

1. Open a rule with **File → Open YARA File…**.
2. Choose **File → Select Scan Folder…** and select the files to scan.
3. Click **Scan**, then open a matching file in the hex editor.

**Save Rule**, **Format YARA**, and **Scan** sit above the editor.
Use **Settings → Editor Settings…** for fonts, server URLs, and API keys.
The **Help** menu includes offline guides and searchable YARA-X reference material.

## Use a server

A public domain is optional: you can connect by LAN IP over HTTPS.
Start with the [server cheatsheet](docs/CHEATSHEET.md#connect-to-a-server-by-lan-ip).
It covers Docker startup, the CA certificate, and desktop settings for Windows/Linux.
For Internet hosting, follow the [public deployment guide](docs/API_SECURITY.md#public-deployment-with-automatic-https).

Rules persist in the mounted database across container rebuilds and restarts.
Keep separate [backups](docs/REPOSITORY_BACKUPS.md); deleting the data volume deletes
its rules. The shared API key is managed in Settings and grants administrator access.

## Find the right guide

| I want to… | Read |
|---|---|
| Copy a common command or fix a connection error | [Cheatsheet](docs/CHEATSHEET.md) |
| Use the editor, repository, hex tools, or CFG | [User guide](docs/USER_GUIDE.md) |
| Find a keyboard shortcut | [Shortcuts](docs/KEYBOARD_SHORTCUTS.md) |
| Recover work after a crash | [Recovery and troubleshooting](docs/RECOVERY_AND_TROUBLESHOOTING.md) |
| Back up, export, or move rules to another server | [Repository backups](docs/REPOSITORY_BACKUPS.md) |
| Configure HTTPS, storage, or API access | [Deployment and security](docs/API_SECURITY.md) |
| Call an API endpoint | [API reference](docs/API_REFERENCE.md) |
| Develop, test, or add a plugin | [Development](docs/DEVELOPMENT.md) |
| Customize the theme | [Theming](docs/THEMING.md) |
| Use XPRESS Huffman decompression | [Recipe guide](docs/XPRESS_HUFFMAN.md) |
| Understand editor syntax support and limits | [Editor toolkit](modules/yarax-editor/README.md) |
