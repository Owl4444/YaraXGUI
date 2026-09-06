"""MWDB Retrohunt plugin — scan MWDB samples server-to-server.

Provides:
  - GUI dock for submitting retrohunt jobs and viewing results
  - API endpoint POST /scan/mwdb for headless/mobile clients
  - Scanner backend for MWDB job execution
"""

from __future__ import annotations

import sys
from pathlib import Path

_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from plugins.base import register_plugin
from pydantic import BaseModel, Field

plugin = register_plugin(
    name="mwdb",
    description="MWDB integration — browse, search, and retrohunt",
    version="1.0.0",
    author="YaraXGUI",
)

# ── Request model ────────────────────────────────────────────────

class MwdbScanRequest(BaseModel):
    rule_text: str = Field(..., max_length=1048576, description="YARA rule source code")
    mwdb_url: str = Field(..., max_length=2048, description="MWDB API URL")
    mwdb_token: str = Field(..., max_length=8192, description="MWDB API key")
    query: str | None = Field(None, max_length=4096, description="Lucene search query")
    file_hash: str | None = Field(None, pattern=r"^[a-fA-F0-9]{64}$", description="Scan single file by hash")
    limit: int = Field(100, ge=1, le=1000, description="Max files to scan")
    batch_size: int = Field(50, ge=1, le=100, description="Files per MWDB page")
    include_misses: bool = Field(False, description="Include non-matching files")
    parallel_downloads: int = Field(4, ge=1, le=16, description="Concurrent downloads")


# ── GUI Dock ─────────────────────────────────────────────────────

@plugin.dock(title="MWDB", area="right")
def create_dock(ctx):
    return _MwdbRetrohuntDock(ctx)


def _MwdbRetrohuntDock(ctx):
    """Build the MWDB retrohunt dock widget."""
    import json
    import urllib.request
    from yaraxgui.network import api_url as normalize_api_url, api_urlopen, mwdb_urlopen, safe_sample_name, save_download
    from functools import partial
    from yaraxgui.credentials import load_setting_secret

    from PySide6.QtCore import Qt, QTimer, QThread, Signal as QSignal
    from PySide6.QtWidgets import (
        QApplication, QComboBox, QHBoxLayout, QHeaderView, QLabel,
        QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
        QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
        QCheckBox, QGroupBox, QFormLayout, QProgressBar,
    )

    class _Worker(QThread):
        """Generic background worker that runs a callable."""
        finished = QSignal(object)  # result or exception
        progress = QSignal(str)     # status message

        def __init__(self, func, *args, **kwargs):
            super().__init__()
            self._func = func
            self._args = args
            self._kwargs = kwargs

        def run(self):
            try:
                result = self._func(
                    *self._args, **self._kwargs)
                self.finished.emit(result)
            except Exception as e:
                self.finished.emit(e)

    class Dock(QWidget):
        def __init__(self):
            super().__init__()
            self._job_id = None
            self._poll_timer = QTimer(self)
            self._poll_timer.setInterval(1000)
            self._poll_timer.timeout.connect(self._poll_status)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.setSpacing(4)

            # ── Connection ───────────────────────────────
            conn_group = QGroupBox("MWDB Connection")
            conn_form = QFormLayout(conn_group)

            self._url_input = QLineEdit()
            self._url_input.setPlaceholderText("https://mwdb.example.com/api/")
            conn_form.addRow("MWDB URL:", self._url_input)

            # Auth mode selector
            self._auth_combo = QComboBox()
            self._auth_combo.addItems(["API Key", "Username / Password"])
            self._auth_combo.currentIndexChanged.connect(self._on_auth_mode_changed)
            conn_form.addRow("Auth Mode:", self._auth_combo)

            # API Key field
            self._token_input = QLineEdit()
            self._token_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._token_input.setPlaceholderText("MWDB API key")
            self._token_label = QLabel("API Token:")
            conn_form.addRow(self._token_label, self._token_input)

            # Username/Password fields (hidden by default)
            self._user_input = QLineEdit()
            self._user_input.setPlaceholderText("MWDB username")
            self._user_label = QLabel("Username:")
            conn_form.addRow(self._user_label, self._user_input)

            self._pass_input = QLineEdit()
            self._pass_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._pass_input.setPlaceholderText("MWDB password")
            self._pass_label = QLabel("Password:")
            conn_form.addRow(self._pass_label, self._pass_input)

            # Hide user/pass by default
            self._user_input.setVisible(False)
            self._user_label.setVisible(False)
            self._pass_input.setVisible(False)
            self._pass_label.setVisible(False)

            # Connect button
            connect_row = QHBoxLayout()
            self._connect_btn = QPushButton("Connect")
            self._connect_btn.clicked.connect(self._on_connect)
            connect_row.addWidget(self._connect_btn)
            self._conn_status = QLabel("")
            connect_row.addWidget(self._conn_status, 1)
            conn_form.addRow(connect_row)

            self._mwdb_token_cache = ""  # cached token after login

            # ── Main splitter: connection + tabs ─────────
            main_splitter = QSplitter(Qt.Orientation.Vertical)
            main_splitter.addWidget(conn_group)

            # ── Tabs: Search / Retrohunt ─────────────────
            from PySide6.QtWidgets import QTabWidget
            self._tabs = QTabWidget()

            # -- Search tab --
            search_tab = QWidget()
            search_layout = QVBoxLayout(search_tab)
            search_layout.setContentsMargins(4, 4, 4, 4)

            search_row = QHBoxLayout()
            self._search_input = QLineEdit()
            self._search_input.setPlaceholderText(
                "Paste hash or Lucene query (file.type:PE, file.name:*.dll)")
            self._search_input.returnPressed.connect(self._on_search)
            search_row.addWidget(self._search_input, 1)
            search_btn = QPushButton("Search")
            search_btn.clicked.connect(self._on_search)
            search_row.addWidget(search_btn)
            search_layout.addLayout(search_row)

            self._search_table = QTableWidget(0, 5)
            self._search_table.setHorizontalHeaderLabels(
                ["Name", "SHA256", "Size", "Type", "Comments"])
            self._search_table.setEditTriggers(
                QTableWidget.EditTrigger.NoEditTriggers)
            self._search_table.setSelectionBehavior(
                QTableWidget.SelectionBehavior.SelectRows)
            self._search_table.setAlternatingRowColors(True)
            self._search_table.verticalHeader().setVisible(False)
            shdr = self._search_table.horizontalHeader()
            shdr.setStretchLastSection(True)
            for _col in range(5):
                shdr.setSectionResizeMode(_col, QHeaderView.ResizeMode.Interactive)
            self._search_table.setColumnWidth(0, 200)
            self._search_table.setColumnWidth(1, 120)
            self._search_table.setColumnWidth(2, 70)
            self._search_table.setContextMenuPolicy(
                Qt.ContextMenuPolicy.CustomContextMenu)
            self._search_table.customContextMenuRequested.connect(
                self._on_search_context_menu)
            search_layout.addWidget(self._search_table, 1)

            self._search_status = QLabel("")
            search_layout.addWidget(self._search_status)

            self._tabs.addTab(search_tab, "Browse / Search")

            # -- Retrohunt tab --
            retro_tab = QWidget()
            retro_layout = QVBoxLayout(retro_tab)
            retro_layout.setContentsMargins(4, 4, 4, 4)

            query_group = QGroupBox("Retrohunt Settings")
            query_form = QFormLayout(query_group)

            self._query_input = QLineEdit()
            self._query_input.setPlaceholderText(
                "Lucene query (e.g. file.type:PE) — leave empty for recent files")
            query_form.addRow("Query:", self._query_input)

            self._hash_input = QLineEdit()
            self._hash_input.setPlaceholderText(
                "Single file hash (overrides query)")
            query_form.addRow("File Hash:", self._hash_input)

            opts_row = QHBoxLayout()
            opts_row.addWidget(QLabel("Limit:"))
            self._limit_spin = QSpinBox()
            self._limit_spin.setRange(1, 1000)
            self._limit_spin.setValue(100)
            opts_row.addWidget(self._limit_spin)

            self._misses_check = QCheckBox("Include misses")
            opts_row.addWidget(self._misses_check)
            query_form.addRow(opts_row)

            retro_layout.addWidget(query_group)

            # ── Action ───────────────────────────────────
            action_row = QHBoxLayout()
            self._scan_btn = QPushButton("  Scan MWDB  ")
            self._scan_btn.setObjectName("scanMwdbBtn")
            self._scan_btn.setStyleSheet(
                "#scanMwdbBtn {"
                "  font-weight: bold;"
                "  padding: 6px 18px;"
                "  border: 2px solid #4CAF50;"
                "  border-radius: 4px;"
                "}"
                "#scanMwdbBtn:hover {"
                "  background-color: #4CAF50;"
                "  color: #fff;"
                "}"
            )
            self._scan_btn.clicked.connect(self._on_start)
            action_row.addWidget(self._scan_btn)

            self._cancel_btn = QPushButton("Cancel")
            self._cancel_btn.setEnabled(False)
            self._cancel_btn.clicked.connect(self._on_cancel)
            action_row.addWidget(self._cancel_btn)
            retro_layout.addLayout(action_row)

            # ── Progress ─────────────────────────────────
            self._progress = QProgressBar()
            self._progress.setVisible(False)
            retro_layout.addWidget(self._progress)

            self._status = QLabel("")
            retro_layout.addWidget(self._status)

            # ── Results table ────────────────────────────
            self._table = QTableWidget(0, 6)
            self._table.setHorizontalHeaderLabels(
                ["File", "SHA256", "Size", "Rules", "Patterns", "Tags"])
            self._table.setEditTriggers(
                QTableWidget.EditTrigger.NoEditTriggers)
            self._table.setSelectionBehavior(
                QTableWidget.SelectionBehavior.SelectRows)
            self._table.setAlternatingRowColors(True)
            self._table.verticalHeader().setVisible(False)
            hdr = self._table.horizontalHeader()
            hdr.setStretchLastSection(True)
            for _col in range(6):
                hdr.setSectionResizeMode(_col, QHeaderView.ResizeMode.Interactive)
            self._table.setColumnWidth(0, 180)
            self._table.setColumnWidth(1, 120)
            self._table.setColumnWidth(2, 70)
            self._table.setColumnWidth(3, 150)
            self._table.setColumnWidth(4, 60)

            self._table.setSelectionMode(
                QTableWidget.SelectionMode.ExtendedSelection)
            self._table.clicked.connect(
                lambda idx: self._show_match_details(idx.row()))
            self._table.setContextMenuPolicy(
                Qt.ContextMenuPolicy.CustomContextMenu)
            self._table.customContextMenuRequested.connect(
                self._on_context_menu)

            # ── Splitter: results table + match details ─
            retro_splitter = QSplitter(Qt.Orientation.Vertical)

            retro_splitter.addWidget(self._table)

            # Match details panel
            match_widget = QWidget()
            match_layout = QVBoxLayout(match_widget)
            match_layout.setContentsMargins(4, 4, 4, 4)
            match_layout.setSpacing(4)

            nav_row = QHBoxLayout()
            self._match_file_label = QLabel("")
            self._match_file_label.setWordWrap(True)
            nav_row.addWidget(self._match_file_label, 1)

            self._prev_match_btn = QPushButton("< Prev")
            self._prev_match_btn.setEnabled(False)
            self._prev_match_btn.clicked.connect(self._prev_match)
            nav_row.addWidget(self._prev_match_btn)

            self._match_pos_label = QLabel("")
            nav_row.addWidget(self._match_pos_label)

            self._next_match_btn = QPushButton("Next >")
            self._next_match_btn.setEnabled(False)
            self._next_match_btn.clicked.connect(self._next_match)
            nav_row.addWidget(self._next_match_btn)
            match_layout.addLayout(nav_row)

            self._match_table = QTableWidget(0, 5)
            self._match_table.setHorizontalHeaderLabels(
                ["Rule", "Pattern", "Offset", "Hex Dump", "ASCII"])
            self._match_table.setEditTriggers(
                QTableWidget.EditTrigger.NoEditTriggers)
            self._match_table.setSelectionBehavior(
                QTableWidget.SelectionBehavior.SelectRows)
            self._match_table.setAlternatingRowColors(True)
            self._match_table.verticalHeader().setVisible(False)
            mhdr = self._match_table.horizontalHeader()
            mhdr.setStretchLastSection(True)
            mhdr.setSectionResizeMode(
                0, QHeaderView.ResizeMode.Interactive)
            mhdr.setSectionResizeMode(
                1, QHeaderView.ResizeMode.Interactive)
            mhdr.setSectionResizeMode(
                2, QHeaderView.ResizeMode.Interactive)
            mhdr.setSectionResizeMode(
                3, QHeaderView.ResizeMode.Interactive)
            self._match_table.setColumnWidth(0, 130)
            self._match_table.setColumnWidth(1, 80)
            self._match_table.setColumnWidth(2, 90)
            self._match_table.setColumnWidth(3, 220)
            self._match_table.setSelectionMode(
                QTableWidget.SelectionMode.ExtendedSelection)
            self._match_table.setContextMenuPolicy(
                Qt.ContextMenuPolicy.CustomContextMenu)
            self._match_table.customContextMenuRequested.connect(
                self._on_match_context_menu)
            match_layout.addWidget(self._match_table, 1)

            retro_splitter.addWidget(match_widget)
            retro_splitter.setStretchFactor(0, 3)
            retro_splitter.setStretchFactor(1, 2)
            retro_splitter.setChildrenCollapsible(False)

            retro_layout.addWidget(retro_splitter, 1)

            self._current_match_idx = -1
            self._all_matches = []
            self._file_cache: dict[str, bytes] = {}  # sha → bytes (from downloads)

            # ── Summary label ────────────────────────────
            self._summary = QLabel("")
            self._summary.setWordWrap(True)
            retro_layout.addWidget(self._summary)

            self._tabs.addTab(retro_tab, "Retrohunt")

            # -- Upload tab --
            upload_tab = QWidget()
            upload_layout = QVBoxLayout(upload_tab)
            upload_layout.setContentsMargins(4, 4, 4, 4)
            upload_layout.setSpacing(4)

            # File/folder selection
            sel_group = QGroupBox("Select Files to Upload")
            sel_layout = QVBoxLayout(sel_group)

            file_btn_row = QHBoxLayout()
            self._add_files_btn = QPushButton("Add Files...")
            self._add_files_btn.clicked.connect(self._on_add_files)
            file_btn_row.addWidget(self._add_files_btn)

            self._add_folder_btn = QPushButton("Add Folder...")
            self._add_folder_btn.clicked.connect(self._on_add_folder)
            file_btn_row.addWidget(self._add_folder_btn)

            self._clear_files_btn = QPushButton("Clear")
            self._clear_files_btn.clicked.connect(self._on_clear_files)
            file_btn_row.addWidget(self._clear_files_btn)
            sel_layout.addLayout(file_btn_row)

            from PySide6.QtWidgets import QListWidget
            self._upload_file_list = QListWidget()
            self._upload_file_list.setAlternatingRowColors(True)
            sel_layout.addWidget(self._upload_file_list, 1)

            self._upload_file_count = QLabel("0 files selected")
            sel_layout.addWidget(self._upload_file_count)

            upload_layout.addWidget(sel_group, 1)

            # Upload options
            opts_group = QGroupBox("Upload Options")
            opts_form = QFormLayout(opts_group)

            self._upload_family = QLineEdit()
            self._upload_family.setPlaceholderText("(optional)")
            opts_form.addRow("Family:", self._upload_family)

            self._upload_comment = QLineEdit()
            self._upload_comment.setPlaceholderText("(optional)")
            opts_form.addRow("Comment:", self._upload_comment)

            upload_layout.addWidget(opts_group)

            # Upload button + status
            upload_btn_row = QHBoxLayout()
            self._upload_btn = QPushButton("Upload to MWDB")
            self._upload_btn.clicked.connect(self._on_upload_to_mwdb)
            upload_btn_row.addWidget(self._upload_btn)
            upload_layout.addLayout(upload_btn_row)

            self._upload_progress = QProgressBar()
            self._upload_progress.setVisible(False)
            upload_layout.addWidget(self._upload_progress)

            self._upload_status = QLabel("")
            self._upload_status.setWordWrap(True)
            upload_layout.addWidget(self._upload_status)

            self._tabs.addTab(upload_tab, "Upload")

            self._upload_paths: list[str] = []

            main_splitter.addWidget(self._tabs)
            main_splitter.setStretchFactor(0, 0)  # connection: compact
            main_splitter.setStretchFactor(1, 1)  # tabs: expand
            main_splitter.setChildrenCollapsible(False)
            layout.addWidget(main_splitter, 1)

            # Restore saved MWDB settings
            try:
                self._url_input.setText(
                    ctx.get_setting('mwdb_url', ''))
                self._token_input.setText(
                    load_setting_secret('mwdb_token', 'mwdb_token', ctx.get_setting))
                auth_mode = ctx.get_setting('mwdb_auth_mode', 0)
                self._auth_combo.setCurrentIndex(auth_mode)
            except Exception:
                pass

        # ── Upload methods ────────────────────────────────

        def _on_add_files(self):
            from PySide6.QtWidgets import QFileDialog
            files, _ = QFileDialog.getOpenFileNames(
                self, "Select Files to Upload")
            if files:
                for f in files:
                    if f not in self._upload_paths:
                        self._upload_paths.append(f)
                self._refresh_upload_list()

        def _on_add_folder(self):
            from PySide6.QtWidgets import QFileDialog
            folder = QFileDialog.getExistingDirectory(
                self, "Select Folder to Upload")
            if folder:
                import os
                for root, dirs, fnames in os.walk(folder):
                    for fn in fnames:
                        fp = os.path.join(root, fn)
                        if fp not in self._upload_paths:
                            self._upload_paths.append(fp)
                self._refresh_upload_list()

        def _on_clear_files(self):
            self._upload_paths.clear()
            self._refresh_upload_list()

        def _refresh_upload_list(self):
            self._upload_file_list.clear()
            for p in self._upload_paths:
                self._upload_file_list.addItem(
                    Path(p).name)
            total_size = sum(
                Path(p).stat().st_size
                for p in self._upload_paths
                if Path(p).is_file())
            self._upload_file_count.setText(
                f"{len(self._upload_paths)} files "
                f"({self._fsize(total_size)})")

        def _on_upload_to_mwdb(self):
            if not self._upload_paths:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.warning(
                    self, "No Files",
                    "Add files or a folder first.")
                return

            token = self._ensure_token()
            if not token:
                return

            api_base = self._get_mwdb_api_base()
            family = self._upload_family.text().strip()
            comment = self._upload_comment.text().strip()
            paths = list(self._upload_paths)

            self._upload_progress.setVisible(True)
            self._upload_progress.setMaximum(0)
            self._upload_status.setText("Zipping and uploading...")
            self._upload_btn.setEnabled(False)

            def _do_upload():
                import zipfile, tempfile, uuid
                from urllib.parse import urlsplit
                if urlsplit(api_base).scheme != 'https':
                    raise ValueError('MWDB requires an HTTPS endpoint')
                # Unique temporary storage, closed even if zipping fails.
                with tempfile.TemporaryFile() as archive:
                    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for fp in paths:
                            p = Path(fp)
                            if p.is_file():
                                zf.write(fp, p.name)
                    archive.seek(0)
                    zip_data = archive.read(100 * 1024**2 + 1)
                if len(zip_data) > 100 * 1024**2:
                    raise ValueError('Upload archive exceeds 100 MiB; select fewer files')
                boundary = '----YaraXGUI' + uuid.uuid4().hex
                parts = []
                parts.append(
                    f"--{boundary}\r\n"
                    f"Content-Disposition: form-data; "
                    f"name=\"file\"; "
                    f"filename=\"upload.zip\"\r\n"
                    f"Content-Type: application/zip\r\n\r\n"
                    .encode())
                parts.append(zip_data)
                parts.append(b"\r\n")
                if family:
                    parts.append(
                        f"--{boundary}\r\n"
                        f"Content-Disposition: form-data; "
                        f"name=\"family\"\r\n\r\n"
                        f"{family}\r\n".encode())
                if comment:
                    parts.append(
                        f"--{boundary}\r\n"
                        f"Content-Disposition: form-data; "
                        f"name=\"comment\"\r\n\r\n"
                        f"{comment}\r\n".encode())
                parts.append(f"--{boundary}--\r\n".encode())
                body = b"".join(parts)

                req = urllib.request.Request(api_base.rstrip('/') + '/file', data=body,
                    headers={'Authorization': f'Bearer {token}',
                             'Content-Type': f'multipart/form-data; boundary={boundary}'}, method='POST')
                with mwdb_urlopen(req, timeout=120) as resp:
                    response = resp.read(2 * 1024**2 + 1)
                    if len(response) > 2 * 1024**2:
                        raise ValueError('MWDB response exceeds 2 MiB')
                    return json.loads(response)

            def _on_upload_done(result):
                self._upload_btn.setEnabled(True)
                self._upload_progress.setVisible(False)
                if isinstance(result, Exception):
                    self._upload_status.setText(
                        f"Upload failed: {result}")
                else:
                    sha = result.get("sha256", "?")[:16]
                    self._upload_status.setText(
                        f"Uploaded! SHA256: {sha}...")

            self._upload_worker = _Worker(_do_upload)
            self._upload_worker.finished.connect(_on_upload_done)
            self._upload_worker.start()

        # ── Connection methods ───────────────────────────

        def _on_connect(self):
            """Test MWDB connection and authenticate."""
            mwdb_url = self._url_input.text().strip().rstrip("/")
            if not mwdb_url:
                self._conn_status.setText("Enter MWDB URL")
                return
            try:
                token = self._get_mwdb_token()
                self._mwdb_token_cache = token
                # Test the connection by fetching server info
                api_base = mwdb_url if mwdb_url.endswith("/api") else mwdb_url + "/api"
                req = urllib.request.Request(
                    f"{api_base}/server",
                    headers={"Authorization": f"Bearer {token}"})
                resp = mwdb_urlopen(req, timeout=10)
                info = json.loads(resp.read())
                ver = info.get("server_version", "?")
                self._conn_status.setText(
                    f"Connected (v{ver})")
                self._conn_status.setStyleSheet("")  # use theme color
                try:
                    ctx.save_setting('mwdb_url', mwdb_url)
                    if self._auth_combo.currentIndex() == 0:
                        from yaraxgui.credentials import save_setting_secret, MWDB_TOKEN
                        save_setting_secret(MWDB_TOKEN, 'mwdb_token', token, ctx.save_setting)
                except Exception:
                    pass
            except Exception as e:
                self._conn_status.setText(f"Failed: {str(e)[:60]}")
                self._conn_status.setStyleSheet("")  # use theme color
                self._mwdb_token_cache = ""

        @staticmethod
        def _is_hash(text):
            """Check if text looks like a hex hash (md5/sha1/sha256)."""
            import re
            t = text.strip()
            return bool(re.fullmatch(r'[0-9a-fA-F]{32,64}', t))

        @staticmethod
        def _fsize(n):
            if not n: return "?"
            if n < 1024: return f"{n} B"
            if n < 1024*1024: return f"{n/1024:.1f} KB"
            return f"{n/(1024*1024):.2f} MB"

        def _on_search(self):
            """Search MWDB for files matching the query."""
            if not self._mwdb_token_cache:
                self._search_status.setText(
                    "Not connected — click Connect first")
                return
            mwdb_url = self._url_input.text().strip().rstrip("/")
            if not mwdb_url.endswith("/api"):
                mwdb_url += "/api"
            query = self._search_input.text().strip()

            headers = {
                "Authorization": f"Bearer {self._mwdb_token_cache}"}
            files = []

            try:
                if self._is_hash(query):
                    # Direct hash lookup — single file
                    url = f"{mwdb_url}/file/{query}"
                    req = urllib.request.Request(url, headers=headers)
                    resp = mwdb_urlopen(req, timeout=15)
                    f = json.loads(resp.read())
                    files = [f]
                else:
                    # Lucene query search
                    url = f"{mwdb_url}/file"
                    params = ["count=50"]
                    if query:
                        params.append(
                            f"query={urllib.request.quote(query)}")
                    url += "?" + "&".join(params)
                    req = urllib.request.Request(url, headers=headers)
                    resp = mwdb_urlopen(req, timeout=15)
                    result = json.loads(resp.read())
                    if isinstance(result, list):
                        files = result
                    else:
                        files = result.get("files", [])
            except urllib.error.HTTPError as e:
                if e.code == 404 and self._is_hash(query):
                    self._search_status.setText(
                        f"Hash not found in MWDB")
                else:
                    self._search_status.setText(
                        f"Search failed (HTTP {e.code})")
                return
            except Exception as e:
                self._search_status.setText(f"Search failed: {e}")
                return

            self._search_results = files
            self._search_table.setRowCount(len(files))
            for i, f in enumerate(files):
                sha = f.get("sha256", f.get("id", ""))
                name_item = QTableWidgetItem(
                    f.get("file_name", sha[:12]))
                name_item.setToolTip(f.get("file_name", ""))

                sha_item = QTableWidgetItem(sha[:12] + "...")
                sha_item.setToolTip(sha)
                sha_item.setData(Qt.ItemDataRole.UserRole, sha)

                self._search_table.setItem(i, 0, name_item)
                self._search_table.setItem(i, 1, sha_item)
                self._search_table.setItem(
                    i, 2, QTableWidgetItem(
                        self._fsize(f.get("file_size", 0))))
                self._search_table.setItem(
                    i, 3, QTableWidgetItem(
                        f.get("file_type", "?")))
                self._search_table.setItem(i, 4, QTableWidgetItem(""))

            self._search_status.setText(f"{len(files)} files found")

            # Fetch comments in background
            if files:
                self._fetch_search_comments(files, headers, mwdb_url)

        def _fetch_search_comments(self, files, headers, mwdb_url):
            """Fetch comments for search results in background."""
            shas = [f.get("sha256", f.get("id", ""))
                    for f in files]

            def _fetch():
                result = {}
                for sha in shas:
                    if not sha:
                        continue
                    try:
                        url = f"{mwdb_url}/object/{sha}/comment"
                        req = urllib.request.Request(
                            url, headers=headers)
                        resp = mwdb_urlopen(req, timeout=5)
                        comments = json.loads(resp.read())
                        if comments:
                            texts = []
                            for c in comments:
                                author = c.get("author", "")
                                body = c.get("comment", "")
                                texts.append(
                                    f"{author}: {body}" if author
                                    else body)
                            result[sha] = texts
                    except Exception:
                        pass
                return result

            def _on_done(result):
                if isinstance(result, Exception):
                    return
                for i, f in enumerate(files):
                    sha = f.get("sha256", f.get("id", ""))
                    texts = result.get(sha, [])
                    if texts:
                        preview = texts[0]
                        if len(texts) > 1:
                            preview += f" (+{len(texts)-1} more)"
                        item = QTableWidgetItem(preview)
                        item.setToolTip("\n---\n".join(texts))
                        self._search_table.setItem(i, 4, item)

            w = _Worker(_fetch)
            w.finished.connect(_on_done)
            w.start()
            # prevent GC
            self._comment_worker = w

        def _fetch_comments_for_sha(self, sha):
            """Fetch comments for a single file. Returns list of dicts."""
            mwdb_url = self._url_input.text().strip().rstrip("/")
            if not mwdb_url.endswith("/api"):
                mwdb_url += "/api"
            headers = {
                "Authorization": f"Bearer {self._mwdb_token_cache}"}
            try:
                url = f"{mwdb_url}/object/{sha}/comment"
                req = urllib.request.Request(url, headers=headers)
                resp = mwdb_urlopen(req, timeout=10)
                return json.loads(resp.read())
            except Exception:
                return []

        def _add_comment_to_sha(self, sha, comment_text):
            """Add a comment to a file in MWDB."""
            mwdb_url = self._url_input.text().strip().rstrip("/")
            if not mwdb_url.endswith("/api"):
                mwdb_url += "/api"
            headers = {
                "Authorization": f"Bearer {self._mwdb_token_cache}",
                "Content-Type": "application/json"}
            body = json.dumps({"comment": comment_text}).encode()
            url = f"{mwdb_url}/object/{sha}/comment"
            req = urllib.request.Request(
                url, data=body, headers=headers, method="POST")
            mwdb_urlopen(req, timeout=10)

        def _delete_comment_from_sha(self, sha, comment_id):
            """Delete a comment from a file in MWDB."""
            mwdb_url = self._url_input.text().strip().rstrip("/")
            if not mwdb_url.endswith("/api"):
                mwdb_url += "/api"
            headers = {
                "Authorization": f"Bearer {self._mwdb_token_cache}"}
            url = f"{mwdb_url}/object/{sha}/comment/{comment_id}"
            req = urllib.request.Request(
                url, headers=headers, method="DELETE")
            mwdb_urlopen(req, timeout=10)

        def _fetch_repo_rules(self):
            """Fetch rule names from the connected rule repository."""
            try:
                api_url = self._build_api_url()
                if not api_url:
                    # No server configured — skip to avoid hang
                    return []
                headers = self._api_headers()
                req = urllib.request.Request(
                    f"{api_url}/repo/rules?limit=200",
                    headers=headers)
                resp = api_urlopen(req, ctx.get_setting, timeout=3)
                rules = json.loads(resp.read())
                return rules
            except Exception:
                return []

        def _on_search_context_menu(self, pos):
            item = self._search_table.itemAt(pos)
            if item:
                self._search_table.setCurrentItem(item)
            row = self._search_table.currentRow()
            if row < 0 or not hasattr(self, '_search_results'):
                return
            if row >= len(self._search_results):
                return
            f = self._search_results[row]
            sha = f.get("sha256", f.get("id", ""))
            fname = f.get("file_name", sha[:12])

            from PySide6.QtWidgets import QMenu, QInputDialog
            menu = QMenu(self)
            act_sha = menu.addAction("Copy SHA256")
            act_name = menu.addAction("Copy Filename")
            menu.addSeparator()

            # Comments
            act_view_comments = menu.addAction("View Comments...")
            act_add_comment = menu.addAction("Add Comment...")
            menu.addSeparator()

            # Retrohunt options
            act_retro_editor = menu.addAction(
                "Scan This File (current editor rule)")
            act_retro_repo = menu.addAction(
                "Scan This File (pick rule from repo)...")
            menu.addSeparator()
            act_dl = menu.addAction("Download...")
            act_dl_hex = menu.addAction(
                "Download && Open in Hex Editor")

            action = menu.exec(
                self._search_table.viewport().mapToGlobal(pos))

            if action is None:
                return
            elif action == act_sha:
                QApplication.clipboard().setText(sha)
                ctx.status_message(f"SHA256: {sha}")
            elif action == act_name:
                QApplication.clipboard().setText(fname)
            elif action == act_view_comments:
                self._show_comments_dialog(sha, fname)
            elif action == act_add_comment:
                self._quick_add_comment(sha, row)
            elif action == act_retro_editor:
                self._hash_input.setText(sha)
                self._tabs.setCurrentIndex(1)
            elif action == act_retro_repo:
                self._pick_repo_rule_and_scan(sha)
            elif action == act_dl:
                self._download_search_file(f, open_hex=False)
            elif action == act_dl_hex:
                self._download_search_file(f, open_hex=True)

        def _pick_repo_rule_and_scan(self, sha):
            """Show a dialog to pick a rule from the repo, then scan."""
            from PySide6.QtWidgets import (
                QDialog, QVBoxLayout, QListWidget, QListWidgetItem,
                QDialogButtonBox, QLineEdit, QMessageBox)

            rules = self._fetch_repo_rules()
            if not rules:
                QMessageBox.information(
                    self, "No Rules",
                    "No rules found in the repository.\n\n"
                    "Make sure the YaraXGUI server URL is set in "
                    "Settings > Connections.")
                return

            dlg = QDialog(self)
            dlg.setWindowTitle("Pick Rule from Repository")
            dlg.setMinimumSize(400, 350)
            layout = QVBoxLayout(dlg)

            search = QLineEdit()
            search.setPlaceholderText("Filter rules...")
            layout.addWidget(search)

            lst = QListWidget()
            for rule in rules:
                rname = rule.get("name", "?")
                family = rule.get("family", "")
                label = rname
                if family:
                    label += f"  [{family}]"
                item = QListWidgetItem(label)
                item.setData(Qt.ItemDataRole.UserRole, rule)
                lst.addItem(item)
            layout.addWidget(lst, 1)

            def _filter(text):
                t = text.lower()
                for i in range(lst.count()):
                    item = lst.item(i)
                    item.setHidden(t not in item.text().lower())
            search.textChanged.connect(_filter)

            btns = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Ok
                | QDialogButtonBox.StandardButton.Cancel)
            btns.accepted.connect(dlg.accept)
            btns.rejected.connect(dlg.reject)
            lst.doubleClicked.connect(dlg.accept)
            layout.addWidget(btns)

            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            sel = lst.currentItem()
            if not sel:
                return
            rule = sel.data(Qt.ItemDataRole.UserRole)
            rule_text = rule.get("rule_text", "")
            if rule_text:
                ctx.load_rule_to_editor(
                    rule_text, rule.get("name", "repo"))
            self._hash_input.setText(sha)
            self._tabs.setCurrentIndex(1)

        def _download_search_file(self, file_info, open_hex=False):
            """Download a file from MWDB browse/search results."""
            sha = file_info.get("sha256", file_info.get("id", ""))
            fname = safe_sample_name(file_info.get("file_name", sha[:12]))
            if not sha:
                return
            token = self._ensure_token()
            if not token:
                return

            from PySide6.QtWidgets import QFileDialog
            if open_hex:
                dl_dir = self._get_download_dir()
                if not dl_dir:
                    return
                dest = str(Path(dl_dir) / fname)
            else:
                dest, _ = QFileDialog.getSaveFileName(
                    self, "Save MWDB File", fname, "All files (*)")
                if not dest:
                    return

            api_base = self._get_mwdb_api_base()
            try:
                req = urllib.request.Request(
                    f"{api_base}/file/{sha}/download",
                    headers={"Authorization": f"Bearer {token}"})
                resp = mwdb_urlopen(req, timeout=120)
                with resp:
                    data = resp.read(100 * 1024**2 + 1)
                if len(data) > 100 * 1024**2:
                    raise ValueError('Download exceeds 100 MiB')
                if open_hex:
                    dest = str(save_download(dl_dir, fname, data))
                else:
                    Path(dest).write_bytes(data)
                ctx.status_message(
                    f"Downloaded: {fname} ({len(data):,} bytes)")
            except Exception as e:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.warning(self, "Download Failed", str(e))
                return

            if open_hex:
                try:
                    ctx.open_hex_editor(str(dest))
                except Exception as e:
                    from PySide6.QtWidgets import QMessageBox
                    QMessageBox.information(
                        self, "Downloaded",
                        f"File saved to:\n{dest}\n\n"
                        f"Could not open hex editor: {e}")

        def _on_auth_mode_changed(self, index):
            is_token = index == 0
            self._token_input.setVisible(is_token)
            self._token_label.setVisible(is_token)
            self._user_input.setVisible(not is_token)
            self._user_label.setVisible(not is_token)
            self._pass_input.setVisible(not is_token)
            self._pass_label.setVisible(not is_token)
            try:
                ctx.save_setting('mwdb_auth_mode', index)
            except Exception:
                pass

        def _get_mwdb_token(self):
            """Get API token — either directly or by logging in with user/pass."""
            if self._auth_combo.currentIndex() == 0:
                return self._token_input.text().strip()

            # Login with username/password to get a token
            mwdb_url = self._url_input.text().strip().rstrip("/")
            user = self._user_input.text().strip()
            passwd = self._pass_input.text().strip()
            if not user or not passwd:
                raise ValueError("Username and password are required")

            # Handle both http://host:port and http://host:port/api
            base = mwdb_url.rstrip("/")
            if not base.endswith("/api"):
                base += "/api"
            login_url = f"{base}/auth/login"
            payload = json.dumps({"login": user, "password": passwd}).encode()
            req = urllib.request.Request(
                login_url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST")
            try:
                resp = mwdb_urlopen(req, timeout=10)
                data = json.loads(resp.read())
                token = data.get("token", "")
                if not token:
                    raise ValueError("Login succeeded but no token returned")
                self._status.setText("MWDB login successful")
                return token
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode()[:200]
                except Exception:
                    pass
                raise ValueError(f"MWDB login failed (HTTP {e.code}): {body}")

        def _build_api_url(self):
            """Build the YaraXGUI API server URL from the repo dock settings."""
            # Use the same server as the rule repository if configured
            try:
                url = ctx.get_setting('repo_server_url', '')
                if url:
                    return normalize_api_url(url, ctx.get_setting)
            except Exception:
                pass
            return ""

        def _api_headers(self):
            headers = {"Content-Type": "application/json"}
            try:
                from yaraxgui.credentials import api_server_key
                key = api_server_key(ctx.get_setting)
                if key:
                    headers["X-API-Key"] = key
            except Exception:
                pass
            return headers

        def _on_start(self):
            mwdb_url = self._url_input.text().strip()
            if not mwdb_url:
                QMessageBox.warning(self, "Missing", "MWDB URL is required.")
                return

            try:
                mwdb_token = self._get_mwdb_token()
            except ValueError as e:
                QMessageBox.warning(self, "Auth Failed", str(e))
                return
            if not mwdb_token:
                QMessageBox.warning(self, "Missing",
                                    "API token or credentials are required.")
                return

            # Save settings
            try:
                ctx.save_setting('mwdb_url', mwdb_url)
                if self._auth_combo.currentIndex() == 0:
                    from yaraxgui.credentials import save_setting_secret, MWDB_TOKEN
                    save_setting_secret(MWDB_TOKEN, 'mwdb_token', mwdb_token, ctx.save_setting)
            except Exception:
                pass

            # Get YARA rule from editor
            rule_text = ctx.get_editor_text()
            if not rule_text.strip():
                QMessageBox.warning(self, "No Rule",
                                    "Write a YARA rule in the editor first.")
                return

            file_hash = self._hash_input.text().strip() or None
            query = self._query_input.text().strip() or None

            # Ensure URL has /api suffix for the server-side scanner
            mwdb_api_url = mwdb_url if mwdb_url.endswith("/api") else mwdb_url + "/api"

            # Submit to API server
            api_url = self._build_api_url()
            payload = {
                "rule_text": rule_text,
                "mwdb_url": mwdb_api_url,
                "mwdb_token": mwdb_token,
                "query": query,
                "file_hash": file_hash,
                "limit": self._limit_spin.value(),
                "batch_size": 50,
                "include_misses": self._misses_check.isChecked(),
            }

            self._scan_btn.setEnabled(False)
            self._cancel_btn.setEnabled(True)
            self._progress.setVisible(True)
            self._progress.setMaximum(self._limit_spin.value())
            self._progress.setValue(0)
            self._table.setRowCount(0)
            self._status.setText("Submitting scan job...")

            def _submit():
                body = json.dumps(payload).encode()
                req = urllib.request.Request(
                    f"{api_url}/scan/mwdb",
                    data=body,
                    headers=self._api_headers(),
                    method="POST")
                resp = api_urlopen(req, ctx.get_setting, timeout=30)
                return json.loads(resp.read())

            def _on_submitted(result):
                if isinstance(result, Exception):
                    self._scan_btn.setEnabled(True)
                    self._cancel_btn.setEnabled(False)
                    self._progress.setVisible(False)
                    self._status.setText(f"Failed: {result}")
                    return
                self._job_id = result.get("job_id")
                self._status.setText(
                    f"Job {self._job_id}: "
                    f"{result.get('message', 'started')}")
                self._poll_timer.start()

            self._submit_worker = _Worker(_submit)
            self._submit_worker.finished.connect(_on_submitted)
            self._submit_worker.start()

        def _on_cancel(self):
            if not self._job_id:
                return
            api_url = self._build_api_url()
            try:
                req = urllib.request.Request(
                    f"{api_url}/scan/{self._job_id}",
                    headers=self._api_headers(),
                    method="DELETE")
                api_urlopen(req, ctx.get_setting, timeout=5)
                self._status.setText("Cancel requested")
            except Exception:
                pass

        def _poll_status(self):
            if not self._job_id:
                self._poll_timer.stop()
                return
            if hasattr(self, '_poll_worker') and self._poll_worker and self._poll_worker.isRunning():
                return  # previous poll still running
            api_url = self._build_api_url()

            def _fetch():
                req = urllib.request.Request(
                    f"{api_url}/scan/{self._job_id}",
                    headers=self._api_headers())
                resp = api_urlopen(req, ctx.get_setting, timeout=5)
                return json.loads(resp.read())

            def _on_poll_done(result):
                if isinstance(result, Exception):
                    return
                self._handle_poll_data(result)

            self._poll_worker = _Worker(_fetch)
            self._poll_worker.finished.connect(_on_poll_done)
            self._poll_worker.start()

        def _handle_poll_data(self, data):

            status = data.get("status", "")
            progress = data.get("progress", {})
            scanned = progress.get("scanned", 0)
            total = progress.get("total", 0)
            matches = progress.get("matches", 0)
            current = progress.get("current_file", "")

            if total > 0:
                self._progress.setMaximum(total)
            self._progress.setValue(scanned)
            self._status.setText(
                f"{status}: {scanned}/{total} scanned, "
                f"{matches} hits — {current}")

            if status in ("completed", "failed", "cancelled"):
                self._poll_timer.stop()
                self._scan_btn.setEnabled(True)
                self._cancel_btn.setEnabled(False)
                self._load_results()

        def _load_results(self):
            if not self._job_id:
                return
            api_url = self._build_api_url()
            self._status.setText("Loading results...")

            def _fetch_results():
                req = urllib.request.Request(
                    f"{api_url}/scan/{self._job_id}/results",
                    headers=self._api_headers())
                resp = api_urlopen(req, ctx.get_setting, timeout=30)
                return json.loads(resp.read())

            def _on_results(result):
                if isinstance(result, Exception):
                    self._status.setText(
                        f"Failed to load results: {result}")
                    return
                self._display_results(result)

            self._results_worker = _Worker(_fetch_results)
            self._results_worker.finished.connect(_on_results)
            self._results_worker.start()

        def _display_results(self, data):
            self._hits = data.get("hits", [])
            stats = data.get("stats", {})
            errors = data.get("error_messages", [])

            self._status.setText(
                f"Done: {stats.get('matches', 0)} hits, "
                f"{stats.get('scanned', 0)} scanned")

            # Summary
            summary_parts = []
            if stats.get('skipped', 0):
                summary_parts.append(
                    f"{stats['skipped']} skipped (size filter)")
            if stats.get('errors', 0):
                summary_parts.append(f"{stats['errors']} errors")
            if errors:
                summary_parts.append(f"Last error: {errors[-1][:80]}")
            self._summary.setText(" | ".join(summary_parts))

            # Format file sizes
            def _fsize(n):
                if not n: return "?"
                if n < 1024: return f"{n} B"
                if n < 1024*1024: return f"{n/1024:.1f} KB"
                return f"{n/(1024*1024):.2f} MB"

            self._table.setRowCount(len(self._hits))
            for i, hit in enumerate(self._hits):
                fname = hit.get("filename", "?")
                sha = hit.get("mwdb_sha256",
                              hit.get("sha256", ""))
                fsize = hit.get("file_size", 0)
                rules = hit.get("matched_rules", [])
                rule_names = ", ".join(
                    r.get("identifier", "") for r in rules)
                pattern_count = sum(
                    len(p.get("matches", []))
                    for r in rules
                    for p in r.get("patterns", []))
                tags = set()
                for r in rules:
                    tags.update(r.get("tags", []))

                name_item = QTableWidgetItem(fname)
                name_item.setToolTip(fname)

                sha_item = QTableWidgetItem(sha[:12] + "...")
                sha_item.setToolTip(sha)
                sha_item.setData(Qt.ItemDataRole.UserRole, sha)

                self._table.setItem(i, 0, name_item)
                self._table.setItem(i, 1, sha_item)
                self._table.setItem(i, 2, QTableWidgetItem(_fsize(fsize)))
                self._table.setItem(i, 3, QTableWidgetItem(rule_names))
                self._table.setItem(
                    i, 4, QTableWidgetItem(str(pattern_count)))
                self._table.setItem(
                    i, 5, QTableWidgetItem(", ".join(sorted(tags))))

            self._progress.setVisible(False)

            # Auto-select first hit to show match details
            if self._hits:
                self._table.selectRow(0)
                self._show_match_details(0)

        def _selected_hit(self):
            row = self._table.currentRow()
            if hasattr(self, '_hits') and 0 <= row < len(self._hits):
                return self._hits[row]
            return None

        # ── Match details ────────────────────────────────

        def _show_match_details(self, hit_row, file_data=None):
            """Populate match details for the selected hit.

            Auto-fetches file bytes from MWDB if not cached, so
            hex/ascii previews always show real data.
            """
            if not hasattr(self, '_hits') or hit_row < 0:
                return
            if hit_row >= len(self._hits):
                return
            hit = self._hits[hit_row]
            fname = hit.get("filename", "?")
            sha = (hit.get("mwdb_sha256", "")
                   or hit.get("sha256", ""))

            # Check cache from previous downloads
            if not file_data and sha:
                file_data = self._file_cache.get(sha)
            self._match_file_label.setText(
                f"<b>{fname}</b> — {sha[:16]}...")

            # Build flat match list
            self._all_matches = []
            for rule in hit.get("matched_rules", []):
                rname = rule.get("identifier", "")
                for pat in rule.get("patterns", []):
                    pid = pat.get("identifier", "")
                    for m in pat.get("matches", []):
                        self._all_matches.append(
                            (rname, pid, m))

            self._match_table.setRowCount(len(self._all_matches))
            for i, (rname, pid, m) in enumerate(self._all_matches):
                off = m.get("offset", 0)
                ln = m.get("length", 0)

                # Try: server-embedded snippet → downloaded bytes → fallback
                hexd = m.get("hex_dump", "")
                ascii_p = m.get("data_preview", "")

                if not hexd and file_data and off < len(file_data):
                    snippet = file_data[off:off + min(ln, 64)]
                    hexd = " ".join(f"{b:02X}" for b in snippet)
                    ascii_p = "".join(
                        chr(b) if 0x20 <= b < 0x7F else "."
                        for b in snippet)
                elif not hexd:
                    hexd = f"0x{off:08X} +{ln} bytes"
                    ascii_p = f"({ln} bytes)"

                self._match_table.setItem(
                    i, 0, QTableWidgetItem(rname))
                self._match_table.setItem(
                    i, 1, QTableWidgetItem(pid))
                self._match_table.setItem(
                    i, 2, QTableWidgetItem(f"0x{off:08X}"))
                self._match_table.setItem(
                    i, 3, QTableWidgetItem(hexd))
                self._match_table.setItem(
                    i, 4, QTableWidgetItem(ascii_p))

            self._current_match_idx = 0 if self._all_matches else -1
            self._update_match_nav()

        def _update_match_nav(self):
            n = len(self._all_matches)
            has = n > 0
            self._prev_match_btn.setEnabled(
                has and self._current_match_idx > 0)
            self._next_match_btn.setEnabled(
                has and self._current_match_idx < n - 1)
            if has and self._current_match_idx >= 0:
                self._match_pos_label.setText(
                    f"{self._current_match_idx + 1}/{n}")
                self._match_table.selectRow(self._current_match_idx)
            else:
                self._match_pos_label.setText("")

        def _prev_match(self):
            if self._current_match_idx > 0:
                self._current_match_idx -= 1
                self._update_match_nav()

        def _next_match(self):
            if self._current_match_idx < len(self._all_matches) - 1:
                self._current_match_idx += 1
                self._update_match_nav()

        # ── Match details context menu ───────────────────
        def _on_match_context_menu(self, pos):
            row = self._match_table.rowAt(pos.y())
            if row < 0 or row >= len(self._all_matches):
                return
            self._match_table.selectRow(row)

            from PySide6.QtWidgets import QMenu
            menu = QMenu(self)

            rname, pid, m = self._all_matches[row]
            off = m.get("offset", 0)
            ln = m.get("length", 0)

            # Resolve the parent hit from the main results table
            hit_row = self._table.currentRow()
            hit = (self._hits[hit_row]
                   if hasattr(self, '_hits') and 0 <= hit_row < len(self._hits)
                   else None)

            # ── Open in hex editor ──────────────────────
            act_dl_hex = menu.addAction(
                "Download && Open in Hex Editor")
            act_dl_hex_at = menu.addAction(
                f"Download && Open at Offset  (0x{off:08X})")
            act_dl_hex.setEnabled(hit is not None)
            act_dl_hex_at.setEnabled(hit is not None)
            menu.addSeparator()

            # ── Copy actions ────────────────────────────
            act_rule = menu.addAction(f"Copy Rule Name  ({rname})")
            act_pattern = menu.addAction(f"Copy Pattern  ({pid})")
            act_offset = menu.addAction(f"Copy Offset  (0x{off:08X})")
            menu.addSeparator()

            hex_item = self._match_table.item(row, 3)
            hex_text = hex_item.text() if hex_item else ""
            act_hex = menu.addAction("Copy Hex Dump")
            act_hex.setEnabled(bool(hex_text))

            ascii_item = self._match_table.item(row, 4)
            ascii_text = ascii_item.text() if ascii_item else ""
            act_ascii = menu.addAction("Copy ASCII")
            act_ascii.setEnabled(bool(ascii_text))

            menu.addSeparator()

            act_yara = menu.addAction("Copy as YARA Hex  { AA BB ... }")
            act_yara.setEnabled(bool(hex_text))

            menu.addSeparator()
            act_all = menu.addAction("Copy All Matches (TSV)")

            action = menu.exec(
                self._match_table.viewport().mapToGlobal(pos))
            if action is None:
                return
            elif action == act_dl_hex:
                self._download_file(hit, open_hex=True)
            elif action == act_dl_hex_at:
                self._download_file(hit, open_hex=True,
                                    goto_offset=off, select_len=ln)
            elif action == act_rule:
                QApplication.clipboard().setText(rname)
            elif action == act_pattern:
                QApplication.clipboard().setText(pid)
            elif action == act_offset:
                QApplication.clipboard().setText(f"0x{off:08X}")
            elif action == act_hex:
                QApplication.clipboard().setText(hex_text)
            elif action == act_ascii:
                QApplication.clipboard().setText(ascii_text)
            elif action == act_yara:
                QApplication.clipboard().setText(f"{{ {hex_text} }}")
            elif action == act_all:
                lines = ["Rule\tPattern\tOffset\tHex Dump\tASCII"]
                for i in range(self._match_table.rowCount()):
                    cols = []
                    for c in range(self._match_table.columnCount()):
                        item = self._match_table.item(i, c)
                        cols.append(item.text() if item else "")
                    lines.append("\t".join(cols))
                QApplication.clipboard().setText("\n".join(lines))
                ctx.status_message(
                    f"Copied {self._match_table.rowCount()} matches")

        # ── Context menu (download + copy) ───────────────

        def _on_context_menu(self, pos):
            # Determine the row directly from the y position — more reliable
            # than itemAt() which can return None on cell borders/empty areas.
            row = self._table.rowAt(pos.y())
            if row < 0:
                return
            self._table.selectRow(row)
            if not hasattr(self, '_hits') or row >= len(self._hits):
                return
            hit = self._hits[row]
            if not hit:
                return
            from PySide6.QtWidgets import QMenu, QFileDialog
            menu = QMenu(self)

            sha = (hit.get("mwdb_sha256", "")
                   or hit.get("sha256", ""))
            fname = hit.get("filename", "?")

            act_dl = menu.addAction("Download...")
            act_dl_hex = menu.addAction(
                "Download && Open in Hex Editor")
            menu.addSeparator()

            # Comments
            act_view_comments = menu.addAction("View Comments...")
            act_add_comment = menu.addAction("Add Comment...")
            menu.addSeparator()

            act_sha = menu.addAction("Copy SHA256")
            act_md5 = menu.addAction("Copy MD5")
            act_name = menu.addAction("Copy Filename")
            menu.addSeparator()

            rules = hit.get("matched_rules", [])
            rule_names = [r.get("identifier", "") for r in rules]
            act_rules = None
            if rule_names:
                act_rules = menu.addAction(
                    f"Copy Rule Names ({len(rule_names)})")

            menu.addSeparator()
            cur_dir = self._get_download_dir(prompt_if_unset=False)
            act_change_dir = menu.addAction(
                f"Change Download Folder"
                f"{' (' + cur_dir + ')' if cur_dir else ''}")

            # Multi-select download
            selected = self._table.selectionModel().selectedRows()
            act_dl_multi = None
            if len(selected) > 1:
                act_dl_multi = menu.addAction(
                    f"Download {len(selected)} Selected...")

            action = menu.exec(
                self._table.viewport().mapToGlobal(pos))

            if action is None:
                return
            elif action == act_dl:
                self._download_file(hit, open_hex=False)
            elif action == act_dl_hex:
                self._download_file(hit, open_hex=True)
            elif action == act_view_comments:
                self._show_comments_dialog(sha, fname)
            elif action == act_add_comment:
                self._quick_add_comment(sha)
            elif action == act_sha:
                QApplication.clipboard().setText(sha)
                ctx.status_message(f"SHA256: {sha}")
            elif action == act_md5:
                QApplication.clipboard().setText(
                    hit.get("md5", ""))
                ctx.status_message(f"MD5: {hit.get('md5', '')}")
            elif action == act_name:
                QApplication.clipboard().setText(fname)
            elif act_rules and action == act_rules:
                QApplication.clipboard().setText(
                    "\n".join(rule_names))
            elif action == act_change_dir:
                from PySide6.QtWidgets import QFileDialog
                new_dir = QFileDialog.getExistingDirectory(
                    self, "Set MWDB Download Folder",
                    cur_dir or "")
                if new_dir:
                    ctx.save_setting("mwdb_download_dir", new_dir)
                    ctx.status_message(
                        f"Download folder: {new_dir}")
            elif act_dl_multi and action == act_dl_multi:
                self._download_multi(selected)

        # ── Comment helpers ──────────────────────────────

        def _show_comments_dialog(self, sha, fname=""):
            """Dialog showing all comments with ability to add/delete."""
            from PySide6.QtWidgets import (
                QDialog, QVBoxLayout, QHBoxLayout, QListWidget,
                QListWidgetItem, QPushButton, QDialogButtonBox,
                QInputDialog, QMessageBox)

            comments = self._fetch_comments_for_sha(sha)

            dlg = QDialog(self)
            dlg.setWindowTitle(
                f"Comments — {fname or sha[:16]}")
            dlg.setMinimumWidth(500)
            dlg.setMinimumHeight(300)
            layout = QVBoxLayout(dlg)

            clist = QListWidget()
            clist.setAlternatingRowColors(True)
            clist.setWordWrap(True)
            for c in comments:
                author = c.get("author", "")
                body = c.get("comment", "")
                cid = c.get("id", "")
                ts = c.get("timestamp", "")
                display = f"[{author}] {body}"
                if ts:
                    display += f"  ({ts})"
                item = QListWidgetItem(display)
                item.setData(Qt.ItemDataRole.UserRole, cid)
                item.setToolTip(body)
                clist.addItem(item)
            layout.addWidget(clist, 1)

            if not comments:
                clist.addItem("(no comments)")

            btn_row = QHBoxLayout()
            add_btn = QPushButton("Add Comment")
            del_btn = QPushButton("Delete Selected")
            btn_row.addWidget(add_btn)
            btn_row.addWidget(del_btn)
            btn_row.addStretch()
            close_btn = QPushButton("Close")
            btn_row.addWidget(close_btn)
            layout.addLayout(btn_row)

            close_btn.clicked.connect(dlg.accept)

            def _on_add():
                text, ok = QInputDialog.getMultiLineText(
                    dlg, "Add Comment",
                    f"Comment for {fname or sha[:16]}:", "")
                if ok and text.strip():
                    try:
                        self._add_comment_to_sha(sha, text.strip())
                        item = QListWidgetItem(
                            f"[you] {text.strip()}")
                        # Remove "(no comments)" placeholder
                        for i in range(clist.count()):
                            if clist.item(i).text() == "(no comments)":
                                clist.takeItem(i)
                                break
                        clist.addItem(item)
                        ctx.status_message("Comment added")
                    except Exception as e:
                        QMessageBox.warning(
                            dlg, "Error",
                            f"Failed to add comment: {e}")

            def _on_del():
                item = clist.currentItem()
                if not item:
                    return
                cid = item.data(Qt.ItemDataRole.UserRole)
                if not cid:
                    return
                reply = QMessageBox.question(
                    dlg, "Delete Comment",
                    "Delete this comment?",
                    QMessageBox.StandardButton.Yes
                    | QMessageBox.StandardButton.No)
                if reply != QMessageBox.StandardButton.Yes:
                    return
                try:
                    self._delete_comment_from_sha(sha, cid)
                    clist.takeItem(clist.row(item))
                    ctx.status_message("Comment deleted")
                except Exception as e:
                    QMessageBox.warning(
                        dlg, "Error",
                        f"Failed to delete comment: {e}")

            add_btn.clicked.connect(_on_add)
            del_btn.clicked.connect(_on_del)
            dlg.exec()

        def _quick_add_comment(self, sha, search_row=None):
            """Quick add a comment via input dialog."""
            from PySide6.QtWidgets import QInputDialog
            text, ok = QInputDialog.getMultiLineText(
                self, "Add Comment",
                f"Comment for {sha[:16]}...:", "")
            if ok and text.strip():
                try:
                    self._add_comment_to_sha(sha, text.strip())
                    ctx.status_message("Comment added")
                    # Update search table comment cell if applicable
                    if (search_row is not None
                            and search_row >= 0
                            and search_row < self._search_table.rowCount()):
                        existing = self._search_table.item(
                            search_row, 4)
                        cur = existing.text() if existing else ""
                        if cur:
                            new_text = f"{text.strip()} | {cur}"
                        else:
                            new_text = text.strip()
                        item = QTableWidgetItem(new_text)
                        item.setToolTip(new_text)
                        self._search_table.setItem(
                            search_row, 4, item)
                except Exception as e:
                    QMessageBox.warning(
                        self, "Error",
                        f"Failed to add comment: {e}")

        # ── Download helpers ─────────────────────────────

        def _get_mwdb_api_base(self):
            url = self._url_input.text().strip().rstrip("/")
            if not url.endswith("/api"):
                url += "/api"
            return url

        def _ensure_token(self):
            """Make sure we have a valid MWDB token."""
            if self._mwdb_token_cache:
                return self._mwdb_token_cache
            # Try to get one
            try:
                token = self._get_mwdb_token()
                self._mwdb_token_cache = token
                return token
            except Exception:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.warning(
                    self, "Not Connected",
                    "Click Connect first to authenticate with MWDB.")
                return None

        def _get_download_dir(self, prompt_if_unset=True):
            """Get the configured download directory.

            On first call (or if not set), prompts the user to pick one
            and saves it to settings.
            """
            dl_dir = ""
            try:
                dl_dir = ctx.get_setting("mwdb_download_dir", "")
            except Exception:
                pass
            if not dl_dir and prompt_if_unset:
                from PySide6.QtWidgets import QFileDialog
                dl_dir = QFileDialog.getExistingDirectory(
                    self, "Set MWDB Download Folder")
                if dl_dir:
                    try:
                        ctx.save_setting("mwdb_download_dir", dl_dir)
                    except Exception:
                        pass
            return dl_dir

        def _download_file(self, hit, open_hex=False,
                           goto_offset=None, select_len=0):
            sha = (hit.get("mwdb_sha256", "")
                   or hit.get("sha256", ""))
            fname = safe_sample_name(hit.get("filename", sha[:12]))
            if not sha:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.warning(
                    self, "Error",
                    "No SHA256 hash found for this file.")
                return
            token = self._ensure_token()
            if not token:
                return

            from PySide6.QtWidgets import QFileDialog, QMessageBox

            if open_hex:
                # Use configured download dir (prompt if first time)
                dl_dir = self._get_download_dir()
                if not dl_dir:
                    return
                dest = str(Path(dl_dir) / fname)
            else:
                # Manual save — let user pick location
                default_dir = self._get_download_dir(
                    prompt_if_unset=False) or ""
                dest, _ = QFileDialog.getSaveFileName(
                    self, "Save MWDB File",
                    str(Path(default_dir) / fname) if default_dir
                    else fname,
                    "All files (*)")
                if not dest:
                    return

            api_base = self._get_mwdb_api_base()
            dl_url = f"{api_base}/file/{sha}/download"

            try:
                req = urllib.request.Request(
                    dl_url,
                    headers={"Authorization": f"Bearer {token}"})
                resp = mwdb_urlopen(req, timeout=120)
                with resp:
                    data = resp.read(100 * 1024**2 + 1)
                if len(data) > 100 * 1024**2:
                    raise ValueError('Download exceeds 100 MiB')
                if open_hex:
                    dest = str(save_download(dl_dir, fname, data))
                else:
                    Path(dest).write_bytes(data)
                ctx.status_message(
                    f"Downloaded: {fname} ({len(data):,} bytes) "
                    f"to {dest}")
            except urllib.error.HTTPError as e:
                QMessageBox.warning(
                    self, "Download Failed",
                    f"HTTP {e.code} from {dl_url}\n\n"
                    f"Check that the MWDB token is valid.")
                return
            except Exception as e:
                QMessageBox.warning(
                    self, "Download Failed", str(e))
                return

            # Re-populate match details with real hex/ascii
            # now that we have the actual file bytes
            row = self._table.currentRow()
            if row >= 0:
                self._show_match_details(row, file_data=data)

            if open_hex:
                try:
                    ctx.open_hex_editor(str(dest))
                    try:
                        ctx.set_hex_match_data(
                            hit.get("matched_rules", []), data)
                    except Exception:
                        pass
                    # Navigate to the specific match offset if requested
                    if goto_offset is not None:
                        try:
                            ctx.hex_goto_offset(
                                goto_offset, select_len)
                        except Exception:
                            pass
                except Exception as e:
                    QMessageBox.information(
                        self, "Downloaded",
                        f"File saved to:\n{dest}\n\n"
                        f"Could not open hex editor: {e}")

        def _download_multi(self, selected_rows):
            token = self._ensure_token()
            if not token:
                return
            dest_dir = self._get_download_dir()
            if not dest_dir:
                return

            api_base = self._get_mwdb_api_base()
            downloaded = 0
            for idx in selected_rows:
                row = idx.row()
                if row >= len(self._hits):
                    continue
                hit = self._hits[row]
                sha = (hit.get("mwdb_sha256", "")
                       or hit.get("sha256", ""))
                fname = safe_sample_name(hit.get("filename", sha[:12]))
                if not sha:
                    continue
                try:
                    req = urllib.request.Request(
                        f"{api_base}/file/{sha}/download",
                        headers={"Authorization":
                                 f"Bearer {token}"})
                    resp = mwdb_urlopen(req, timeout=60)
                    with resp:
                        data = resp.read(100 * 1024**2 + 1)
                    if len(data) > 100 * 1024**2:
                        raise ValueError('Download exceeds 100 MiB')
                    save_download(dest_dir, fname, data)
                    downloaded += 1
                except Exception:
                    pass

            ctx.status_message(
                f"Downloaded {downloaded}/{len(selected_rows)} files "
                f"to {dest_dir}")

    return Dock()


# ── API endpoint ─────────────────────────────────────────────────

@plugin.api("POST", "/scan/mwdb", tags=["MWDB"])
async def start_mwdb_scan(req: MwdbScanRequest):
    """Scan files from an MWDB instance directly (server-to-server).

    YaraXGUI connects to MWDB, downloads files, scans them, and returns
    results.  Any HTTP client submits the job and polls for results
    -- no file data ever touches the client.
    """
    manager = _get_scan_manager()

    if len(req.rule_text.encode("utf-8")) > 1024 * 1024:
        from fastapi import HTTPException
        raise HTTPException(413, "Rule text too large")

    from fastapi import HTTPException
    from api.workers import WorkerBusy
    try:
        job = manager.create_mwdb_job(
            rule_text=req.rule_text,
            mwdb_url=req.mwdb_url,
            mwdb_token=req.mwdb_token,
            query=req.query,
            file_hash=req.file_hash,
            limit=req.limit,
            batch_size=req.batch_size,
            include_misses=req.include_misses,
            parallel_downloads=req.parallel_downloads,
        )
        manager.submit(job)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except WorkerBusy as exc:
        raise HTTPException(429, str(exc)) from exc

    target = (f"file={req.file_hash}" if req.file_hash
              else f"query={req.query or 'recent files'}, limit={req.limit}")
    return {
        "job_id": job.job_id,
        "status": job.status,
        "message": f"MWDB scan job created ({target})",
    }


# ── Scanner backend ──────────────────────────────────────────────

# ── Helpers ──────────────────────────────────────────────────────

_manager = None


def _get_scan_manager():
    global _manager
    if _manager is None:
        from api.jobs import SecureScanManager
        from api.security import SecurityPolicy
        _manager = SecureScanManager(SecurityPolicy.from_env())
    return _manager


def set_scan_manager(manager):
    """Called by the API server to share its ScanManager instance."""
    global _manager
    _manager = manager
