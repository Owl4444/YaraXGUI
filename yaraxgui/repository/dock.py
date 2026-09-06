"""Browse and manage a persistent local or remote YARA rule repository."""

from __future__ import annotations

import json
import re
import urllib.request
from urllib.parse import urlencode

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)


class _RuleMetadataDialog(QDialog):
    """Dialog to view/edit rule metadata fields."""

    def __init__(self, title: str = "Rule Metadata",
                 name: str = "", family: str = "", tags: str = "",
                 author: str = "", description: str = "",
                 source: str = "",
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(450)
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._name = QLineEdit(name)
        form.addRow("Name:", self._name)
        self._family = QLineEdit(family)
        form.addRow("Family:", self._family)
        self._tags = QLineEdit(tags)
        self._tags.setPlaceholderText("comma-separated")
        form.addRow("Tags:", self._tags)
        self._author = QLineEdit(author)
        form.addRow("Author:", self._author)
        self._description = QLineEdit(description)
        form.addRow("Description:", self._description)
        self._source = QLineEdit(source)
        form.addRow("Source:", self._source)

        layout.addLayout(form)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def metadata(self) -> dict:
        result = {
            "name": self._name.text().strip(),
            "family": self._family.text().strip(),
            "tags": self._tags.text().strip(),
            "author": self._author.text().strip(),
            "description": self._description.text().strip(),
            "source": self._source.text().strip(),
        }
        return result


class RuleRepoDock(QWidget):
    """Dock widget for browsing a local or remote YARA rule repository."""

    rule_load_requested = Signal(str, str)  # (rule_text, title)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._server_url = ""
        self._get_setting = lambda key, default=None: default
        self._local_repo = None  # RuleRepository for local mode
        self._is_local = True
        self._rules: list[dict] = []
        self._offset = 0
        self._page_size = 200
        self._has_next_page = False
        self._active_query = (None, None)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # ── Mode selector ────────────────────────────────────
        mode_row = QHBoxLayout()
        self._mode_combo = QComboBox()
        self._mode_combo.addItems(["Local (no server needed)", "Remote Server"])
        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        mode_row.addWidget(QLabel("Mode:"))
        mode_row.addWidget(self._mode_combo, 1)
        layout.addLayout(mode_row)

        # ── Server row (remote only) ─────────────────────────
        self._remote_widget = QWidget()
        remote_layout = QVBoxLayout(self._remote_widget)
        remote_layout.setContentsMargins(0, 0, 0, 0)
        remote_layout.setSpacing(4)

        srv_row = QHBoxLayout()
        srv_row.addWidget(QLabel("Server:"))
        self._server_input = QLineEdit()
        self._server_input.setPlaceholderText("https://yara.example.com")
        self._server_input.setToolTip(
            "Public HTTPS URL of the YaraXGUI API server.\n"
            "Docker Compose: https://your-domain (port 443). Port 7777 is internal.\n"
            "Manage the API key and additional CA certificate in Settings.")
        srv_row.addWidget(self._server_input, 1)
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.clicked.connect(self._on_connect)
        srv_row.addWidget(self._connect_btn)
        remote_layout.addLayout(srv_row)

        credentials_hint = QLabel("API key: managed in Settings → Editor Settings…")
        credentials_hint.setWordWrap(True)
        remote_layout.addWidget(credentials_hint)

        layout.addWidget(self._remote_widget)
        self._remote_widget.setVisible(False)  # local mode by default

        # ── Local DB row ─────────────────────────────────────
        self._local_widget = QWidget()
        local_layout = QHBoxLayout(self._local_widget)
        local_layout.setContentsMargins(0, 0, 0, 0)
        self._local_status = QLabel("")
        self._local_status.setWordWrap(True)
        self._local_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        local_layout.addWidget(self._local_status, 1)
        layout.addWidget(self._local_widget)

        # ── Search row ───────────────────────────────────────
        search_row = QHBoxLayout()
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search rules...")
        self._search_input.returnPressed.connect(self._on_search)
        search_row.addWidget(self._search_input, 1)

        self._family_combo = QComboBox()
        self._family_combo.addItem("All Families")
        self._family_combo.setMinimumWidth(120)
        search_row.addWidget(self._family_combo)

        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self._on_search)
        search_row.addWidget(search_btn)
        layout.addLayout(search_row)

        # ── Status label ─────────────────────────────────────
        self._status = QLabel("")
        self._status.setWordWrap(True)
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        self._status.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        layout.addWidget(self._status)

        # ── Results table ────────────────────────────────────
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Name", "Family", "Tags", "Author", "Source"])
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.itemSelectionChanged.connect(self._update_actions)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(1, 100)
        self._table.setColumnWidth(2, 120)
        self._table.setColumnWidth(3, 100)
        self._table.setColumnWidth(4, 80)
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        layout.addWidget(self._table, 1)

        page_row = QHBoxLayout()
        self._previous_btn = QPushButton("Previous")
        self._previous_btn.clicked.connect(self._previous_page)
        self._next_btn = QPushButton("Next")
        self._next_btn.clicked.connect(self._next_page)
        page_row.addWidget(self._previous_btn)
        page_row.addStretch()
        page_row.addWidget(self._next_btn)
        layout.addLayout(page_row)

        # ── Action buttons ───────────────────────────────────
        btn_row = QHBoxLayout()
        self._load_btn = QPushButton("Edit Rule")
        self._load_btn.clicked.connect(self._on_load)
        btn_row.addWidget(self._load_btn)

        self._edit_btn = QPushButton("Metadata…")
        self._edit_btn.clicked.connect(self._on_edit)
        btn_row.addWidget(self._edit_btn)

        self._upload_btn = QPushButton("Add as New…")
        self._upload_btn.clicked.connect(self._on_upload)
        btn_row.addWidget(self._upload_btn)

        self._delete_btn = QPushButton("Delete")
        self._delete_btn.clicked.connect(self._on_delete)
        btn_row.addWidget(self._delete_btn)
        layout.addLayout(btn_row)
        edit_hint = QLabel("Edit a rule, then use Update Repository above the editor to save changes.")
        edit_hint.setWordWrap(True)
        layout.addWidget(edit_hint)

        # Initialize local mode (must be after all widgets are created)
        self._init_local_repo()

    # ── Public API ───────────────────────────────────────────

    def set_server(self, url: str):
        """Pre-fill remote server fields. Does NOT switch mode — local is primary."""
        self._server_input.setText(url)

    def get_editor_text_func(self):
        """Returns a callable that gets the current editor text.
        Set by MainWindow after creation."""
        return getattr(self, '_get_editor_text', lambda: "")

    # ── Local repo ──────────────────────────────────────────

    def _init_local_repo(self):
        """Initialize a local SQLite rule repository (no server needed)."""
        self._is_local = True
        try:
            from api.rule_repo import RuleRepository
            from yaraxgui.repository.local_store import prepare_local_database
            db_path = prepare_local_database()
            self._local_repo = RuleRepository(db_path)
            self.destroyed.connect(self._local_repo.close)
            self._local_status.setToolTip(str(db_path))
            self._on_search()
        except Exception as e:
            self._local_status.setText(f"Local DB error: {e}")
            self._status.setText("Local database unavailable")
        self._update_actions()

    def _on_mode_changed(self, index: int):
        """Switch between local and remote mode."""
        is_remote = index == 1
        self._remote_widget.setVisible(is_remote)
        self._local_widget.setVisible(not is_remote)
        self._is_local = not is_remote
        self._clear_results()
        self._search_input.clear()
        self._family_combo.clear()
        self._family_combo.addItem("All Families")
        if self._is_local:
            if not self._local_repo:
                self._init_local_repo()
            else:
                self._on_search()
        else:
            self._server_url = ""
            self._status.setText("Enter server URL and click Connect")
        self._update_actions()

    def _require_local_repo(self):
        if self._local_repo is None:
            raise RuntimeError("Local database unavailable")
        return self._local_repo

    # ── Unified data access (local or remote) ────────────────

    def _repo_search(self, **kwargs) -> list[dict]:
        if self._is_local:
            return self._require_local_repo().search(**kwargs)
        return self._api("GET", "/repo/rules" + self._build_query(**kwargs))

    def _repo_get(self, rule_id: int) -> dict | None:
        if self._is_local:
            return self._require_local_repo().get(rule_id)
        return self._api("GET", f"/repo/rules/{rule_id}")

    def _repo_add(self, **fields) -> dict:
        if self._is_local:
            rid = self._require_local_repo().add(**fields)
            return {"id": rid, "message": "Rule added"}
        return self._api("POST", "/repo/rules", fields)

    def _repo_update(self, rule_id: int, **fields) -> dict:
        if self._is_local:
            if not self._require_local_repo().update(rule_id, **fields):
                raise RuntimeError("Rule not found")
            return {"message": "Rule updated"}
        return self._api("PUT", f"/repo/rules/{rule_id}", fields)

    def _repo_delete(self, rule_id: int) -> dict:
        if self._is_local:
            if not self._require_local_repo().delete(rule_id):
                raise RuntimeError("Rule not found")
            return {"message": "Rule deleted"}
        return self._api("DELETE", f"/repo/rules/{rule_id}")

    def _repo_stats(self) -> dict:
        if self._is_local:
            return self._require_local_repo().stats()
        return self._api("GET", "/repo/stats")

    def _repo_families(self) -> list[str]:
        if self._is_local:
            return self._require_local_repo().families()
        return self._api("GET", "/repo/families")

    # ── HTTP helpers (remote only) ───────────────────────────

    def _api(self, method: str, path: str,
             data: dict | None = None) -> dict | list:
        if not self._server_url:
            raise RuntimeError("Connect to a server first")
        from yaraxgui.network import api_url, api_urlopen
        base_url = api_url(self._server_url, self._get_setting)
        configured = self._get_setting('repo_server_url', '')
        if (configured and not getattr(self, '_connecting', False)
                and api_url(configured, self._get_setting) != base_url):
            raise RuntimeError('Server URL changed in Settings. Reconnect the repository before continuing.')
        url = f"{base_url}{path}"
        body = json.dumps(data).encode() if data else None
        headers = {"Content-Type": "application/json"}
        from yaraxgui.credentials import api_server_key
        key = api_server_key(self._get_setting)
        if key:
            headers["X-API-Key"] = key
        req = urllib.request.Request(
            url, data=body, headers=headers, method=method)
        try:
            with api_urlopen(req, self._get_setting, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = json.loads(e.read()).get("detail", "")
            except Exception:
                pass
            raise RuntimeError(f"HTTP {e.code}: {detail or e.reason}")
        except (urllib.error.URLError, OSError) as e:
            from yaraxgui.network import connection_error_message
            raise RuntimeError(connection_error_message(e, base_url)) from e

    # ── Slots ────────────────────────────────────────────────

    def _on_connect(self):
        self._clear_results()
        self._family_combo.clear()
        self._family_combo.addItem("All Families")
        self._server_url = self._server_input.text().strip().rstrip("/")
        self._is_local = False
        if not self._server_url:
            self._status.setText("Enter a server URL")
            self._update_actions()
            return
        self._connecting = True
        try:
            from yaraxgui.network import api_url
            self._server_url = api_url(self._server_url, self._get_setting)
            self._server_input.setText(self._server_url)
            stats = self._repo_stats()
            self._status.setText(
                f"Connected - {stats.get('total_rules', 0)} rules, "
                f"{stats.get('families', 0)} families")
            # Save connection settings for next session
            if hasattr(self, '_save_setting') and self._save_setting:
                self._save_setting('repo_server_url', self._server_url)
            families = self._repo_families()
            self._family_combo.clear()
            self._family_combo.addItem("All Families")
            for f in families:
                self._family_combo.addItem(f)
            self._on_search()
        except Exception as e:
            self._server_url = ""
            self._status.setText(f"Connection failed: {e}")
        finally:
            self._connecting = False
        self._update_actions()

    def _on_search(self):
        self._offset = 0
        self._refresh_results()

    def _refresh_results(self):
        if not self._is_local and not self._server_url:
            return
        q = self._search_input.text().strip() or None
        family = None
        if self._family_combo.currentIndex() > 0:
            family = self._family_combo.currentText()
        if (q, family) != self._active_query:
            self._offset = 0
            self._active_query = (q, family)
        try:
            # Fetch one extra row so navigation reflects actual remaining results.
            rows = self._repo_search(q=q, family=family,
                                     limit=self._page_size + 1, offset=self._offset)
            self._has_next_page = len(rows) > self._page_size
            self._rules = rows[:self._page_size]
            self._populate_table()
            # Update family dropdown
            try:
                families = self._repo_families()
                current = self._family_combo.currentText()
                self._family_combo.clear()
                self._family_combo.addItem("All Families")
                for f in families:
                    self._family_combo.addItem(f)
                idx = self._family_combo.findText(current)
                if idx >= 0:
                    self._family_combo.setCurrentIndex(idx)
            except Exception:
                pass
            if self._is_local:
                stats = self._repo_stats()
                self._local_status.setText(
                    f"Local DB: {stats['total_rules']} rules\n"
                    f"{self._local_status.toolTip()}")
            if self._rules:
                self._status.setText(
                    f"Showing rules {self._offset + 1}–{self._offset + len(self._rules)}"
                    + (" (more available)" if self._has_next_page else ""))
            else:
                self._status.setText("No rules found")
        except Exception as e:
            self._clear_results()
            self._status.setText(f"Search failed: {e}")
        self._update_actions()

    def _clear_results(self):
        self._rules = []
        self._offset = 0
        self._has_next_page = False
        self._populate_table()

    def _previous_page(self):
        self._offset = max(0, self._offset - self._page_size)
        self._refresh_results()

    def _next_page(self):
        if self._has_next_page:
            self._offset += self._page_size
            self._refresh_results()

    def _update_actions(self):
        ready = self._local_repo is not None if self._is_local else bool(self._server_url)
        selected = ready and self._selected_rule() is not None
        for button in (self._load_btn, self._edit_btn, self._delete_btn):
            button.setEnabled(selected)
        self._upload_btn.setEnabled(ready)
        self._upload_btn.setToolTip("Add the current editor contents as a new repository entry.")
        self._previous_btn.setEnabled(ready and self._offset > 0)
        self._next_btn.setEnabled(ready and self._has_next_page)

    @staticmethod
    def _build_query(**params) -> str:
        query = urlencode({k: v for k, v in params.items() if v is not None})
        return "?" + query if query else ""

    def _populate_table(self):
        self._table.clearSelection()
        self._table.setCurrentCell(-1, -1)
        self._table.setRowCount(len(self._rules))
        for i, rule in enumerate(self._rules):
            self._table.setItem(i, 0, QTableWidgetItem(rule.get("name", "")))
            self._table.setItem(i, 1, QTableWidgetItem(rule.get("family", "")))
            self._table.setItem(i, 2, QTableWidgetItem(rule.get("tags", "")))
            self._table.setItem(i, 3, QTableWidgetItem(rule.get("author", "")))
            self._table.setItem(i, 4, QTableWidgetItem(rule.get("source", "")))

    def _selected_rule(self) -> dict | None:
        row = self._table.currentRow()
        if 0 <= row < len(self._rules):
            return self._rules[row]
        return None

    def _on_double_click(self, index):
        self._on_load()

    def _on_load(self):
        rule = self._selected_rule()
        if not rule:
            return
        try:
            current = self._repo_get(rule['id'])
            if not current:
                raise RuntimeError('This rule no longer exists. Refresh the repository list.')
            self._open_repository_editor(current)
        except Exception as exc:
            QMessageBox.warning(self, 'Open rule failed', str(exc))

    def _repository_identity(self):
        if self._is_local:
            return ('local', self._require_local_repo()._db_path)
        return ('remote', self._server_url)

    def _open_repository_editor(self, rule):
        edit = getattr(self, '_edit_repository_rule', None)
        if edit is None:
            self.rule_load_requested.emit(rule['rule_text'], rule['name'])
            return
        from yaraxgui.repository.editor import RepositoryRuleTarget
        origin = self._repository_identity()
        rule_id = rule['id']

        def require_origin():
            if self._repository_identity() != origin:
                raise RuntimeError(
                    'This tab belongs to a different repository connection. '
                    'Switch the repository back to ' + str(origin[1]) + ' before updating or reloading.')

        def read():
            require_origin()
            return self._repo_get(rule_id)

        def update(text, expected_text):
            require_origin()
            return self._repo_update(rule_id, rule_text=text, expected_rule_text=expected_text)

        target = RepositoryRuleTarget(
            identity=(*origin, rule_id),
            location='Local repository' if origin[0] == 'local' else origin[1],
            read=read, update=update, refreshed=self._on_search)
        edit(target, rule)

    def _on_upload(self):
        get_text = getattr(self, '_get_editor_text', None)
        if not get_text:
            return
        editor_text = get_text()
        if not editor_text.strip():
            QMessageBox.warning(self, "Empty", "No rule text in editor.")
            return
        m = re.search(r'rule\s+(\w+)', editor_text)
        default_name = m.group(1) if m else ""

        dlg = _RuleMetadataDialog(
            title="Add as New Repository Rule",
            name=default_name, parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        meta = dlg.metadata()
        if not meta["name"]:
            QMessageBox.warning(self, "Name Required", "Rule name is required.")
            return

        try:
            result = self._repo_add(
                name=meta["name"], rule_text=editor_text,
                family=meta.get("family", ""),
                tags=meta.get("tags", ""),
                author=meta.get("author", ""),
                description=meta.get("description", ""),
                source=meta.get("source", ""))
            self._status.setText(
                f"Saved: {meta['name']} (id={result.get('id')})")
            self._on_search()
            if result.get('id') is not None:
                self._open_repository_editor(dict(meta, rule_text=editor_text, id=result['id']))
        except Exception as e:
            QMessageBox.warning(self, "Save Failed", str(e))

    def _on_edit(self):
        """Edit repository labels separately from the full YARA source editor."""
        rule = self._selected_rule()
        if not rule:
            return

        dlg = _RuleMetadataDialog(
            title=f"Edit Metadata: {rule.get('name', '')}",
            name=rule.get("name", ""),
            family=rule.get("family", ""),
            tags=rule.get("tags", ""),
            author=rule.get("author", ""),
            description=rule.get("description", ""),
            source=rule.get("source", ""),
            parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        meta = dlg.metadata()
        if not meta["name"]:
            QMessageBox.warning(self, "Name Required", "Rule name is required.")
            return
        # Only send changed fields
        updates = {}
        for key in ("name", "family", "tags", "author",
                     "description", "source"):
            new_val = meta.get(key, "")
            old_val = rule.get(key, "")
            if new_val != old_val:
                updates[key] = new_val

        if not updates:
            self._status.setText("No changes made")
            return

        try:
            self._repo_update(rule['id'], **updates)
            self._status.setText(f"Updated: {meta.get('name', '')}")
            self._on_search()
        except Exception as e:
            QMessageBox.warning(self, "Update Failed", str(e))

    def _on_delete(self):
        rule = self._selected_rule()
        if not rule:
            return
        reply = QMessageBox.question(
            self, "Delete Rule",
            f"Delete '{rule.get('name')}' from the repository?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            self._repo_delete(rule['id'])
            self._status.setText(f"Deleted: {rule.get('name')}")
            self._on_search()
        except Exception as e:
            QMessageBox.warning(self, "Delete Failed", str(e))

    def _on_context_menu(self, pos):
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        self._table.setCurrentCell(index.row(), 0)
        rule = self._selected_rule()
        if not rule:
            return
        menu = QMenu(self)
        act_load = menu.addAction("Edit Rule")
        act_edit = menu.addAction("Edit Metadata...")
        act_copy = menu.addAction("Copy Rule Text")
        menu.addSeparator()
        act_delete = menu.addAction("Delete")

        action = menu.exec(self._table.viewport().mapToGlobal(pos))
        if action == act_load:
            self._on_load()
        elif action == act_edit:
            self._on_edit()
        elif action == act_copy:
            QApplication.clipboard().setText(rule.get("rule_text", ""))
        elif action == act_delete:
            self._on_delete()
