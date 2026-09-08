# Development

Run commands from the checkout root unless noted otherwise. Use Python 3.12+
and a 64-bit interpreter for the desktop build.

## Setup and launch

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python -m yaraxgui
```

`python mainwindow.py` remains a compatibility entry point. Both launchers
accept files and directories as arguments, and dispatch frozen analysis workers
before importing the GUI. Run from another directory by passing the absolute
path to `mainwindow.py`. Resources resolve relative to the checkout or bundle,
independently of the working directory.

## Code organization

- `yaraxgui/app.py` composes the main window. Editor, scanning, repository,
  recovery, and reusable UI code live in the corresponding subpackages.
- `yaraxgui/editor/services.py`, `yaraxgui/scanning/scanner.py`, and
  `yaraxgui/repository/local_store.py` also serve the API. Keep these modules
  and package initializers free of Qt imports.
- `hex_editor/` contains binary inspection and recipe operations. Expensive
  analysis runs through its worker and cancellation infrastructure.
- `api/` and `plugins/` retain their existing module names and discovery paths.
  Plugins should import application helpers through `yaraxgui.*`.
- `modules/yarax-editor/` is an independent package with its own build metadata,
  tests, reference documentation, and licensed rule corpus. Its language engine
  is shared by desktop and API callers.
- `yaraxgui/ui/forms/mainwindow.ui` is the Designer source;
  `yaraxgui/ui/generated/mainwindow.py` is the checked-in generated UI.
  Regenerate from the root after changing the form:

  ```sh
  pyside6-uic yaraxgui/ui/forms/mainwindow.ui -o yaraxgui/ui/generated/mainwindow.py
  ```

Runtime UI customization belongs outside the generated file. Review the
generated diff and run the GUI tests when updating the form.

## Validation

```sh
python -m pip install pytest httpx hypothesis
python -m pytest
cd modules/yarax-editor
python -m pytest
cd ../..
```

Application tests use Qt's offscreen platform. Run the editor suite from its
own directory so pytest uses its independent configuration and collection rules.
Optional Caddy, Windows/native-code, and external-corpus tests explain their
requirements when skipped. See the editor
package's [validation notes](../modules/yarax-editor/docs/VALIDATION.md) for its
additional corpus and browser checks.

## GitHub Actions

The [CI workflow](../.github/workflows/ci.yml) and
[Windows build workflow](../.github/workflows/windows-build.yml) run on every
push and pull request. Both also support **Actions → Run workflow** once the
workflow files are on the default branch. No repository secrets are required.

| Check | Coverage |
|---|---|
| Application and editor tests | Ubuntu 24.04 and Windows Server 2025, each with 64-bit Python 3.12 and 3.13; includes GUI, API, repository, scanning, and recipe regressions |
| Editor browser and package | Python 3.11, the editor's minimum version; standalone tests, real Chromium interactions, wheel and source archive builds, and installation of the wheel in a fresh environment outside the checkout |
| Headless API container | Linux and Windows Compose configuration validation, Docker image build, then live health, compilation, validation, formatting, and repository requests with temporary storage |
| Windows executable | Python 3.13; runs `compile_to_exe.bat` and produces `YaraXGUI.exe` |

Linux test jobs obtain Caddy from the same `caddy:2` image used in deployment,
so the real proxy/TLS tests run there. Windows jobs exercise the native-code
tests. The external compression corpus remains optional; set `XPRESS_TEST_CORPUS`
to an existing local corpus when running that additional check manually.
Windows checkouts preserve original line endings for the bundled reference
checksum tests, and Python uses UTF-8 on both platforms.

Open a workflow run to see failing steps and download its artifacts. JUnit XML
reports are retained even when tests fail; successful builds provide the editor
wheel/source archive and `YaraXGUI-windows-x64` executable artifact. Artifacts
expire after 14 days. The executable job verifies packaging; desktop behavior
is covered by the application tests. These workflows do not publish releases
or deploy the server.

Each workflow cancels its older run for the same ref when a new run starts.
Dependency downloads use the [setup-python pip cache](https://github.com/actions/setup-python#caching-packages).
The Chromium job installs its browser and system dependencies using the
[Playwright CI setup](https://playwright.dev/python/docs/ci).
Action revisions are pinned to commits with version comments beside them;
update the pin and comment together when upgrading an action.

## Executable build

The Windows entry point remains at the root:

```bat
compile_to_exe.bat py -3.13
```

It installs dependencies and builds `dist\YaraXGUI.exe` using
`packaging/yaraxgui.spec`. An activated environment or an explicit interpreter
path is also supported. For a direct build on the current platform:

```sh
python -m PyInstaller --clean --noconfirm packaging/yaraxgui.spec
```

The spec resolves source files relative to itself and also works when invoked
by absolute path from another directory. Build and distribution directories
are ignored; attach executables to releases instead of committing them. The
bundle includes shared themes, icons, offline help, plugins, and editor-engine
resources. It excludes local settings and databases.

## Headless API

Install `requirements-server.txt` in a separate environment to run without Qt:

```sh
python -m pip install -r requirements-server.txt
YARAXGUI_DEV_MODE=1 python -m api.server
```

On Unix, `scripts/run_api.sh` runs the same server from any working directory.
It reads security settings from the inherited environment and accepts `--host`
and `--port`. Development mode is loopback-only; public mode requires HTTPS
and an API key. Set `YARAXGUI_PYTHON` to an interpreter path if needed; its
default is `python3`. It does not source `.env`; Docker Compose uses the root
`.env` separately. See `.env.example` and [API security and deployment](API_SECURITY.md).

The Docker build copies the application package, but the API only imports its
headless components. Persistent server data belongs on the `/data` volume.

## Local data and repository hygiene

Source settings remain in `config/settings.json`; shared theme definitions
remain in `config/themes.json`. The desktop database still uses its persistent
OS data directory. Migration continues to recognize `config/local_rules.db` at
the old checkout root and beside an installed executable. Moving source files
does not move or reset existing settings, databases, or recovery data.

Keep `.env`, database files, downloads, virtual environments, IDE state, caches,
and compiled executables out of source control. The former root `run.sh` has
been replaced by the shared launcher without embedded credentials. Previously
committed secrets remain in Git history and require credential rotation.


## Plugin development

YaraXGUI uses a drop-in plugin architecture. Plugins are Python files in the `plugins/` directory.

**Built-in plugins:**
- `rule_repository.py` — Rule Repository dock + API endpoints
- `mwdb_retrohunt.py` — MWDB Browse/Search/Retrohunt dock + API endpoint

**Writing a plugin:**

Create a `.py` file in `plugins/`:

```python
from plugins.base import register_plugin

plugin = register_plugin(
    name="my_plugin",
    description="My custom integration",
)

# Add a GUI dock panel
@plugin.dock(title="My Panel", area="right")
def create_dock(ctx):
    from PySide6.QtWidgets import QLabel
    lbl = QLabel("Hello from plugin!")
    return lbl

# Add an API endpoint
@plugin.api("GET", "/my/endpoint", tags=["MyPlugin"])
async def my_endpoint():
    return {"hello": "world"}

# Add a menu action
@plugin.menu_action("My Action", menu="Tools")
def on_action(ctx):
    ctx.status_message("Action triggered!")
```

Restart the app — the dock appears, the API endpoint is live. Delete the file to disable.

**Plugin context** (`ctx`) provides:
- `ctx.get_editor_text()` — current editor content
- `ctx.load_rule_to_editor(text, title)` — open rule in new tab
- `ctx.open_hex_editor(filepath)` — open file in hex editor
- `ctx.get_setting(key, default)` / `ctx.save_setting(key, value)`
- `ctx.status_message(msg)` — show in status bar

Plugins execute as application code. Install plugins you trust; API routes
registered through the framework still pass through the API security middleware.
See the [REST endpoint catalog](API_REFERENCE.md) for built-in routes.

## Windows build troubleshooting

Use `compile_to_exe.bat` without arguments for an active virtual environment,
or pass `py -3.13` or an explicit `python.exe` path. The script prints the
selected interpreter and validates Python 3.12+ / 64-bit. Use `py --list` if
the launcher cannot find your runtime. Close the output executable before
building. Set `YARAXGUI_BUILD_NO_PAUSE=1` for unattended builds.
