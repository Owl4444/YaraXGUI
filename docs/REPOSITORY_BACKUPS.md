# Persistent rules, exports and migration

Repository saves are committed to SQLite on the server. With the supplied
Compose files, `/data/rules.db` is on persistent storage:

| Launcher | Storage on that server |
|---|---|
| Windows: `scripts/compose.bat` | Docker volume `yaraxgui-data`, normally named `yaraxgui_yaraxgui-data` |
| Linux: `scripts/compose.sh` | `${YARAXGUI_DATA_DIR}/rules.db`, default `/mnt/exthdd/yaraxgui-data/rules.db` |

Restarts, rebuilds and container recreation reuse that storage when the Compose
project and mount configuration stay the same. Deleting a volume, using
`down -v`, resetting Docker's data, or losing the disk can still lose rules.
Keep backups on another disk/computer. Unsaved editor changes are not repository
saves. Windows and Linux Docker engines have separate storage until you migrate.

## Back up and export from Windows

Use the updated project files and rebuild the API image once so it contains the
transfer module:

```powershell
.\scripts\compose.bat up -d --build
```

Use Python 3.13 or newer on the host. The tools use only its standard library;
no GUI dependencies are needed. From the project folder, while the source API
is running:

```powershell
py -3.13 scripts/repository.py backup backups/rules-2026-09-06.db
py -3.13 scripts/repository.py export backups/rules-2026-09-06.zip
```

Choose a new filename for each backup. Existing output files are never replaced.
The destination folder is created automatically. If no repository exists yet,
connect to Rule Repository once to initialize it before taking a backup.

- **`.db` backup:** a consistent SQLite snapshot for restoring/migrating the
  repository. It includes rule text, IDs, families, tags, authors, descriptions,
  sources, creation/modification timestamps and the ID sequence.
- **`.zip` export:** one UTF-8 `.yar` file per stored rule and a versioned
  `manifest.json` containing all metadata and the file mapping. Filenames use
  IDs, so duplicate names in different families and unsafe names cannot collide
  or escape the archive folder. The stored source is preserved exactly, including
  comments and line endings; this does not repair or combine the rules into a
  single compilable ruleset. Use the `.db` backup for a lossless server migration.
  The ZIP is for inspecting/sharing sources and consuming metadata in other tools;
  it is not accepted by the database restore command.

Backups include committed changes still in SQLite's WAL. Do not copy only a live
`rules.db` file using `docker cp`; it can omit recent saves in `rules.db-wal`.
The tool uses SQLite's online backup API instead. Concurrent saves made after
the snapshot are not included. Database lock waits are limited to 60 seconds.
Export uses a snapshot too, so its rule text and metadata agree.

Binary data is transferred directly between Python and Docker. Do not pipe a
binary database through PowerShell text redirection. The host helper downloads
to a temporary file and publishes the output only after the container command
succeeds; a failed command leaves no final backup file.

## Migrate or restore on Windows

1. Copy a `.db` backup to the destination server, for example
   `backups/rules-2026-09-06.db`. Prepare its `.env`, API key and HTTPS settings
   using the [deployment guide](API_SECURITY.md). Build the destination image:
   `.\scripts\compose.bat build yaraxgui-api`.
2. If the destination already has rules, back them up first using the backup
   command above and a different filename. Restore replaces the repository;
   it does not merge rules.
3. Stop the destination API and keep it stopped during restore:

   ```powershell
   .\scripts\compose.bat stop yaraxgui-api
   py -3.13 scripts/repository.py restore backups/rules-2026-09-06.db
   ```

   For an existing destination database, explicitly allow replacement:

   ```powershell
   py -3.13 scripts/repository.py restore backups/rules-2026-09-06.db --replace
   ```

4. After a successful restore, start the stack and reconnect the desktop:

   ```powershell
   .\scripts\compose.bat up -d
   ```

The helper refuses restoration while an API container is running, paused or
restarting. The one-off restore container uses the same persistent storage and
non-root user as the API. It does not start the HTTP server or expose a port.
On restore failure, the helper does not restart the API; inspect the error first.
Invalid/unsupported backups are rejected before changing the destination.
The final database replacement is a SQLite transaction: an interrupted copy
rolls back. The supported rule schema and search indexes are rebuilt, preserving
rule data while avoiding installation of triggers/views from the input backup.
Custom database tables and custom schema extensions are not migrated.

## Linux and moving between platforms

On Linux, substitute `python3.13` (or a newer interpreter) for `py -3.13` and
`./scripts/compose.sh` for `.\scripts\compose.bat`. For example, after copying
the Windows backup to Linux:

```sh
./scripts/compose.sh build yaraxgui-api
./scripts/compose.sh stop yaraxgui-api
python3.13 scripts/repository.py restore backups/rules-2026-09-06.db
./scripts/compose.sh up -d
```

Use `--replace` only after backing up an existing destination repository.
The `.db` format is the same on Windows and Linux. The helper automatically uses
the Windows volume on Windows, or the Linux bind mount on Linux/WSL. Use
`--storage windows` or `--storage linux` if intentionally selecting the other
layout, for example when operating Windows named-volume storage from WSL.

Always use the same Compose project name and storage configuration as the API.
The helper explicitly loads the shared platform files, just like the launchers;
custom automatic `compose.override.yaml` files are not loaded. If your deployment
uses custom mounts or Compose files, use the native module with those files via
your own Compose commands, or operate on the stopped database directly.

## Native server / desktop local database

The module also works without Docker and takes an explicit database path:

```sh
python3.13 -m api.repository_transfer backup backup.db --database /srv/yaraxgui/rules.db
python3.13 -m api.repository_transfer export rules.zip --database /srv/yaraxgui/rules.db
# Stop the API (or close the desktop for its local database) before restoring.
python3.13 -m api.repository_transfer restore backup.db --database /srv/yaraxgui/rules.db --replace
```

Run as the database owner. The module defaults to `YARAXGUI_REPO_DB` when set.
The native module cannot detect arbitrary running applications: stop every
writer yourself before restoring. Restore requires the destination parent
folder to exist and be writable.

## Scope and capacity

These are **rule repository** backups. They do not include uploaded samples,
scan history, unsaved editor buffers, `.env`, API keys or Caddy's CA/private keys.
A new server can use its own API key and certificate; configure the desktop for
that server after migration. Preserve/back up other data separately as needed.

The tools stream rows and file contents rather than loading the whole repository
into Python memory. Export and restore need temporary disk space for snapshots
and a rebuilt database. The supplied container has a 512 MiB `/tmp`; large
repositories may need a larger tmpfs and container memory limit before transfer.
Keep the destination repository quota consistent with the source. A backup is
not automatic: run it regularly, store copies off the server, and test a restore
into a separate deployment before relying on it.


## Container reports No module named api.repository_transfer

This error comes from Python inside the container, even when the host script
was launched with `sudo python3.13`. Updating the host checkout does not replace
code in an already running container. Confirm `api/repository_transfer.py` is
present in the server checkout, then rebuild/recreate using the same platform
launcher and storage settings. On Linux:

```sh
sudo ./scripts/compose.sh up -d --build --force-recreate
sudo ./scripts/compose.sh exec -T yaraxgui-api python -m api.repository_transfer --help
sudo python3.13 scripts/repository.py backup backups/rules.db
```

Omit `sudo` if your account already has Docker access. On Windows, use
`.\scripts\compose.bat` for the Compose commands and `py -3.13` for the host
script. This recreates containers while retaining the mounted rule data; do not
use `down -v`. If the module is still missing, check that the build succeeded
and that the launcher targets the intended checkout and Docker engine.
