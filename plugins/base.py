"""YaraXGUI Plugin Framework.

Plugins are Python files in the ``plugins/`` directory.  Each plugin
calls :func:`register_plugin` to declare itself, then uses decorator
methods on the returned :class:`PluginBuilder` to register docks,
API endpoints, scanner backends, and menu actions.

Example minimal plugin::

    from plugins.base import register_plugin

    plugin = register_plugin(
        name="hello_world",
        description="Example plugin",
    )

    @plugin.dock(title="Hello", area="right")
    def create_dock(ctx):
        from PySide6.QtWidgets import QLabel
        return QLabel("Hello from plugin!")

Plugins are loaded at startup by :func:`load_plugins`.  Broken plugins
are skipped with a warning — they never crash the host app.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


# ── Plugin specification ─────────────────────────────────────────

@dataclass
class ApiRoute:
    method: str         # "GET", "POST", "PUT", "DELETE"
    path: str           # e.g. "/repo/rules"
    handler: Callable   # async def handler(...)
    tags: list[str] = field(default_factory=list)
    response_model: Any = None


@dataclass
class MenuAction:
    label: str
    callback: Callable
    menu: str = "Tools"  # which menu bar menu to add to


@dataclass
class PluginSpec:
    """Everything a plugin can provide."""

    name: str
    description: str = ""
    version: str = "1.0.0"
    author: str = ""

    # GUI dock
    dock_factory: Callable | None = None
    dock_title: str = ""
    dock_area: str = "right"  # "left", "right", "bottom"

    # API endpoints
    api_routes: list[ApiRoute] = field(default_factory=list)

    # Scanner backend
    scanner_factory: Callable | None = None
    scanner_source: str = ""  # matches ScanJob.source

    # Menu bar actions
    menu_actions: list[MenuAction] = field(default_factory=list)

    # Plugin-specific settings (defaults)
    settings: dict[str, Any] = field(default_factory=dict)


# ── Global registry ──────────────────────────────────────────────

PLUGIN_REGISTRY: dict[str, PluginSpec] = {}


# ── Plugin builder (returned by register_plugin) ─────────────────

class PluginBuilder:
    """Fluent builder returned by :func:`register_plugin`.

    Use its decorator methods (``.dock()``, ``.api()``, ``.scanner()``,
    ``.menu_action()``) to register components.
    """

    def __init__(self, spec: PluginSpec):
        self._spec = spec

    @property
    def spec(self) -> PluginSpec:
        return self._spec

    # ── Dock decorator ───────────────────────────────────────

    def dock(self, title: str, area: str = "right"):
        """Register a GUI dock widget factory.

        The decorated function receives a :class:`PluginContext` and
        must return a ``QWidget``.
        """
        def decorator(func: Callable):
            self._spec.dock_factory = func
            self._spec.dock_title = title
            self._spec.dock_area = area
            return func
        return decorator

    # ── API endpoint decorator ───────────────────────────────

    def api(self, method: str, path: str, tags: list[str] | None = None,
            response_model=None):
        """Register a FastAPI endpoint."""
        def decorator(func: Callable):
            self._spec.api_routes.append(ApiRoute(
                method=method.upper(),
                path=path,
                handler=func,
                tags=tags or [self._spec.name],
                response_model=response_model,
            ))
            return func
        return decorator

    # ── Scanner backend decorator ────────────────────────────

    def scanner(self, source: str):
        """Register a scanner backend for a given job source.

        The decorated function signature:
        ``def scan(job: ScanJob, scanner: YaraScanner) -> None``
        It should update ``job.progress``, ``job.results``, ``job.status``.
        """
        def decorator(func: Callable):
            self._spec.scanner_factory = func
            self._spec.scanner_source = source
            return func
        return decorator

    # ── Menu action decorator ────────────────────────────────

    def menu_action(self, label: str, menu: str = "Tools"):
        """Register a menu bar action.

        The decorated function receives a :class:`PluginContext`.
        """
        def decorator(func: Callable):
            self._spec.menu_actions.append(MenuAction(
                label=label, callback=func, menu=menu))
            return func
        return decorator


# ── Registration function ────────────────────────────────────────

def register_plugin(name: str, description: str = "",
                    version: str = "1.0.0",
                    author: str = "") -> PluginBuilder:
    """Declare a plugin and return a builder for registering components."""
    spec = PluginSpec(name=name, description=description,
                      version=version, author=author)
    PLUGIN_REGISTRY[name] = spec
    return PluginBuilder(spec)


# ── Plugin context (injected into dock factories) ────────────────

class PluginContext:
    """Safe interface that plugins use to interact with the host app.

    Populated by the host (MainWindow or API server) before calling
    plugin factories.
    """

    def __init__(self):
        self._callbacks: dict[str, Callable] = {}

    def register(self, name: str, callback: Callable):
        self._callbacks[name] = callback

    def __getattr__(self, name: str):
        if name.startswith('_'):
            raise AttributeError(name)
        cb = self._callbacks.get(name)
        if cb is None:
            raise AttributeError(
                f"PluginContext has no '{name}'. "
                f"Available: {list(self._callbacks.keys())}")
        return cb


# ── Plugin loader ────────────────────────────────────────────────

def load_plugins(*directories: str | Path) -> dict[str, PluginSpec]:
    """Import all ``.py`` files from the given directories.

    Each file that calls :func:`register_plugin` will populate
    :data:`PLUGIN_REGISTRY`.  Broken files are skipped with a
    warning printed to stderr.

    Returns the registry for convenience.
    """
    for directory in directories:
        d = Path(directory)
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if (f.suffix != '.py'
                    or f.name.startswith('_')
                    or f.name == 'base.py'):
                continue
            _load_one(f)
    return PLUGIN_REGISTRY


def _load_one(path: Path):
    """Import a single plugin file."""
    mod_name = f"_yaraxgui_plugin_{path.stem}"
    try:
        spec = importlib.util.spec_from_file_location(mod_name, str(path))
        if spec is None or spec.loader is None:
            return
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
    except Exception as e:
        print(f"[plugin] Failed to load {path.name}: {e}", file=sys.stderr)
