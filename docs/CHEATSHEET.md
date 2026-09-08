# YaraXGUI cheatsheet

Common tasks in one place. Run commands from your project folder, such as
`R:\Tools\YaraXGUI\YaraXGUI` on Windows or `/opt/stacks/yaraxgui` on Linux.
Use Python 3.13 or newer for host commands, and the same checkout and Docker
storage layout each time.

[Desktop](#desktop) · [LAN server](#connect-to-a-server-by-lan-ip) ·
[Server commands](#everyday-server-commands) · [Backups](#back-up-export-or-migrate-rules) ·
[Storage](#where-your-rules-live) · [Troubleshooting](#quick-fixes)

## Desktop

Install once using the [README setup commands](../README.md#run-the-desktop-app).

| Task | Windows PowerShell | Linux / macOS |
|---|---|---|
| Start the app | `.\.venv\Scripts\python.exe -m yaraxgui` | `./.venv/bin/python -m yaraxgui` |
| Build the Windows executable | `.\compile_to_exe.bat py -3.13` | See [development](DEVELOPMENT.md#executable-build) |

| In the app | Action |
|---|---|
| Open a rule / scan folder | **File → Open YARA File… / Select Scan Folder…** |
| Save / format / scan | Buttons above the editor |
| Edit a stored repository rule | **Edit Rule → Update Repository → review changes → Confirm Update** |
| Server URL, API key, CA certificate | **Settings → Editor Settings… → Connections & Credentials** |
| Restore the default panel arrangement | **View → Reset Layout** |
| Recover an unsaved draft | **File → Recover Unsaved Work…** |
| Search the current Help page | **Ctrl+F** |
| Zoom hex/text font | **Ctrl+scroll**, **Ctrl++ / Ctrl+−**; **Ctrl+0** resets |

**Ctrl+S** saves, **Ctrl+Shift+F** formats, **Ctrl+Shift+L** checks a rule,
and **Ctrl+Space** requests suggestions. [All shortcuts](KEYBOARD_SHORTCUTS.md).

## Connect to a server by LAN IP

Docker must be running; on Windows use Docker Desktop with Linux containers.
Use the updated project files, including `deployment/Caddyfile`. No domain or
hosts-file change is required. Substitute your server's actual LAN IPv4 address
for **192.168.1.50** throughout.

1. Find the server's IP: `ipconfig` on Windows or `ip -4 addr` on Linux.
   Choose the active LAN adapter, not a Docker/WSL adapter or `0.0.0.0`.
2. Edit `.env` in the project folder. For a **new installation only**, copy
   `.env.example` to `.env` first. Keep existing keys and data settings.

   ```dotenv
   YARAXGUI_DOMAIN=192.168.1.50
   YARAXGUI_API_KEY=<your-existing-or-new-random-key>
   ```

   Generate a new key only if needed:

   | Windows | Linux |
   |---|---|
   | `py -3.13 -c "import secrets; print(secrets.token_urlsafe(32))"` | `python3.13 -c "import secrets; print(secrets.token_urlsafe(32))"` |

3. Apply the settings. Clearing the shell variable prevents an old value from
   overriding `.env`.

   **Windows PowerShell**

   ```powershell
   Remove-Item Env:YARAXGUI_DOMAIN -ErrorAction SilentlyContinue
   .\scripts\compose.bat up -d --build --force-recreate
   .\scripts\compose.bat ps
   ```

   **Linux**

   ```sh
   unset YARAXGUI_DOMAIN
   ./scripts/compose.sh up -d --build --force-recreate
   ./scripts/compose.sh ps
   ```

   On Linux, prefix Docker launcher commands with `sudo` if your account needs
   it. Keep the same Docker engine/context. The API should be **healthy** and
   Caddy **running**. For first-time Linux storage setup, see
   [data-directory preparation](API_SECURITY.md#public-deployment-with-automatic-https).
4. Export Caddy's public CA certificate after Caddy starts:

   **Windows**

   ```powershell
   .\scripts\compose.bat cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
   ```

   **Linux**

   ```sh
   ./scripts/compose.sh cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
   ```

5. Transfer `caddy-root.crt` to the desktop computer through a trusted channel
   and keep it at a stable path. In **Settings → Editor Settings…**, set:

   | Setting | Value |
   |---|---|
   | YaraXGUI Server | `https://192.168.1.50` |
   | Require HTTPS | Enabled |
   | Additional CA (PEM) | Select `caddy-root.crt` |
   | API key | Same key as the server's `.env` |

6. Save settings. In **Rule Repository**, select **Remote Server**, enter the
   same HTTPS URL, and click **Connect**. Allow LAN access to TCP **443** through
   the server firewall. Port **7777** stays internal to Docker.

[Full LAN instructions](API_SECURITY.md#lan-https-by-ip-address-no-domain-needed) ·
[Public-domain deployment](API_SECURITY.md#public-deployment-with-automatic-https).

## Everyday server commands

| Task | Windows PowerShell | Linux |
|---|---|---|
| Start | `.\scripts\compose.bat up -d` | `./scripts/compose.sh up -d` |
| Status | `.\scripts\compose.bat ps` | `./scripts/compose.sh ps` |
| Recent logs | `.\scripts\compose.bat logs --tail=80 yaraxgui-api caddy` | `./scripts/compose.sh logs --tail=80 yaraxgui-api caddy` |
| Apply updated code/config | `.\scripts\compose.bat up -d --build --force-recreate` | `./scripts/compose.sh up -d --build --force-recreate` |
| Stop API for restore | `.\scripts\compose.bat stop yaraxgui-api` | `./scripts/compose.sh stop yaraxgui-api` |
| Stop the stack, keeping data | `.\scripts\compose.bat stop` | `./scripts/compose.sh stop` |

A plain restart does not apply changed `.env` values. Use the apply command.
**Do not use `down -v` to update:** it deletes named volumes, including Windows
rule storage and Caddy's CA. Keep the same project name and storage settings.

## Back up, export, or migrate rules

Run on the server. Backups/exports use the running API container; rebuild after
pulling the transfer tools for the first time. Choose a new output filename each
time. These commands preserve all repository metadata.

**Windows PowerShell**

```powershell
py -3.13 scripts/repository.py backup backups/rules-2026-09-06.db
py -3.13 scripts/repository.py export backups/rules-2026-09-06.zip
```

**Linux:** use `python3.13` instead of `py -3.13`; use `sudo python3.13` if Docker
requires it. The helper automatically chooses the platform's storage layout.

The **`.db`** is a consistent snapshot for migration. The **ZIP** contains `.yar`
files and `manifest.json` for reading/sharing. Keep copies off the server.

To migrate, copy the `.db` to the destination server, configure/build that server,
back up its existing repository, then run there:

```powershell
.\scripts\compose.bat stop yaraxgui-api
py -3.13 scripts/repository.py restore backups/rules-2026-09-06.db
.\scripts\compose.bat up -d
```

If a destination database already exists, add **`--replace`** to the restore
command only after backing it up. Restore replaces the rules; it does not merge.
On Linux substitute `./scripts/compose.sh` and `python3.13`. Restart only after a
successful restore. [Full migration guide and limits](REPOSITORY_BACKUPS.md).

## Where your rules live

| Mode | Location |
|---|---|
| Desktop local, Windows | `%LOCALAPPDATA%\YaraXGUI\local_rules.db` |
| Desktop local, Linux | `$XDG_DATA_HOME/YaraXGUI/local_rules.db`, default `~/.local/share/YaraXGUI/local_rules.db` |
| Desktop local, macOS | `~/Library/Application Support/YaraXGUI/local_rules.db` |
| Docker API, inside container | `/data/rules.db` |
| Docker API, Windows launcher | Volume `yaraxgui-data`, normally `yaraxgui_yaraxgui-data` |
| Docker API, Linux launcher | `${YARAXGUI_DATA_DIR}/rules.db`, default `/mnt/exthdd/yaraxgui-data/rules.db` |

Repository saves persist; unsaved editor changes are separate. Do not copy only
a live `rules.db` with `docker cp`: recent saves may still be in its WAL. Use the
backup tool. Backups cover rules, not uploaded samples, credentials, or certificates.

## Quick fixes

| Symptom | Check / fix |
|---|---|
| `0.0.0.0` / `::` rejected | Put the actual LAN IP in `.env` as `YARAXGUI_DOMAIN`, clear the shell override, then apply the config. |
| `TLSV1_ALERT_INTERNAL_ERROR` | Match the URL to `YARAXGUI_DOMAIN`; use the updated Caddyfile with `default_sni`, then inspect Caddy logs. |
| Certificate verification failed | Select Caddy's exported root certificate in Additional CA; use the IP/name covered by the certificate. |
| Refused / timed-out connection | Check container status, LAN IP, TCP 443 and firewall. |
| HTTP 401/403 | Check the shared API key in Settings and the server's access policy. |
| `/data/uploads` permission denied | Windows: use `scripts/compose.bat`. Linux: prepare the mounted directory for UID/GID 1000. [Storage guide](API_SECURITY.md#windows--docker-desktop-storage). |
| `No module named api.repository_transfer` | Check the file exists on the server, then rebuild/recreate the image. [Exact commands](REPOSITORY_BACKUPS.md#container-reports-no-module-named-apirepository_transfer). |
| Editor assistance pauses on a large file | Above 64 KiB automatic services pause; manual checks/formatting support up to 256 KiB. Saving still works. |
| Hex search takes too long | Cancel the active search. [Search/recovery limits](RECOVERY_AND_TROUBLESHOOTING.md). |

`.env`, certificates/keys, databases and `backups/` are ignored by Git.
Ignore rules do not remove files already tracked. Never paste API keys or private
keys into an issue. [More guides](../README.md#find-the-right-guide).
