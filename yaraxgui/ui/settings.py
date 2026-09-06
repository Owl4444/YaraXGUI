"""Settings dialog for YaraXGUI preferences."""

from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFontComboBox,
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QSpinBox, QVBoxLayout, QMessageBox, QScrollArea, QWidget,
)
from PySide6.QtGui import QFont


class SettingsDialog(QDialog):
    """Modal dialog for configuring UI, editor, and download settings."""

    def __init__(
        self,
        current_ui_font_family: str = "Consolas",
        current_ui_font_size: int = 9,
        current_editor_font_family: str = "Consolas",
        current_editor_font_size: int = 12,
        current_tab_size: int = 4,
        current_download_dir: str = "",
        current_auto_delete: bool = False,
        parent=None,
        **kwargs,
    ):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(450)

        outer = QVBoxLayout(self)
        content = QWidget()
        layout = QVBoxLayout(content)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        outer.addWidget(scroll)
        self.resize(600, min(850, int(self.screen().availableGeometry().height() * .85)))

        # ── UI Appearance ────────────────────────────────────
        ui_group = QGroupBox("UI Appearance")
        ui_form = QFormLayout(ui_group)

        self._ui_font_combo = QFontComboBox()
        self._ui_font_combo.setCurrentFont(QFont(current_ui_font_family))
        ui_form.addRow("UI Font:", self._ui_font_combo)

        self._ui_size_spin = QSpinBox()
        self._ui_size_spin.setRange(6, 24)
        self._ui_size_spin.setValue(current_ui_font_size)
        self._ui_size_spin.setSuffix(" pt")
        ui_form.addRow("UI Font Size:", self._ui_size_spin)

        layout.addWidget(ui_group)

        # ── Editor ───────────────────────────────────────────
        editor_group = QGroupBox("Editor")
        form = QFormLayout(editor_group)

        self._font_combo = QFontComboBox()
        self._font_combo.setFontFilters(QFontComboBox.FontFilter.MonospacedFonts)
        self._font_combo.setCurrentFont(QFont(current_editor_font_family))
        form.addRow("Editor Font:", self._font_combo)

        self._size_spin = QSpinBox()
        self._size_spin.setRange(6, 72)
        self._size_spin.setValue(current_editor_font_size)
        self._size_spin.setSuffix(" pt")
        form.addRow("Editor Font Size:", self._size_spin)

        self._tab_spin = QSpinBox()
        self._tab_spin.setRange(2, 8)
        self._tab_spin.setValue(current_tab_size)
        self._tab_spin.setSuffix(" spaces")
        form.addRow("Tab Width:", self._tab_spin)

        layout.addWidget(editor_group)

        # ── Connections ──────────────────────────────────────
        conn_group = QGroupBox("Connections && Credentials")
        conn_form = QFormLayout(conn_group)

        self._api_url_input = QLineEdit(
            kwargs.get("api_server_url", ""))
        self._api_url_input.setPlaceholderText("https://yara.example.com")
        conn_form.addRow("YaraXGUI Server:", self._api_url_input)

        self._api_https_check = QCheckBox("Require HTTPS (recommended)")
        self._api_https_check.setChecked(kwargs.get("api_https_enabled", True))
        self._api_https_check.setToolTip("Certificates are always verified. Disable only for a localhost HTTP development server.")
        conn_form.addRow("Transport:", self._api_https_check)
        ca_row = QHBoxLayout()
        self._api_ca_input = QLineEdit(kwargs.get("api_ca_file", ""))
        self._api_ca_input.setPlaceholderText("System trust store (default)")
        ca_row.addWidget(self._api_ca_input)
        ca_button = QPushButton("Browse...")
        ca_button.clicked.connect(self._browse_api_ca)
        ca_row.addWidget(ca_button)
        conn_form.addRow("Additional CA (PEM):", ca_row)

        self._api_key_input = QLineEdit(
            kwargs.get("api_server_key", ""))
        self._api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key_input.setPlaceholderText("(stored in OS keyring)")
        conn_form.addRow("API Key:", self._api_key_input)

        self._mwdb_url_input = QLineEdit(
            kwargs.get("mwdb_url", ""))
        self._mwdb_url_input.setPlaceholderText("https://mwdb.example.com")
        conn_form.addRow("MWDB URL:", self._mwdb_url_input)

        self._mwdb_token_input = QLineEdit(
            kwargs.get("mwdb_token", ""))
        self._mwdb_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._mwdb_token_input.setPlaceholderText("(stored in OS keyring)")
        conn_form.addRow("MWDB Token:", self._mwdb_token_input)

        try:
            import yaraxgui.credentials as credential_store
            if credential_store.is_available():
                import keyring
                backend = type(keyring.get_keyring()).__name__
                _sec_label = QLabel(
                    f"<small>Credentials stored securely via "
                    f"{backend}</small>")
            else:
                _sec_label = QLabel(
                    "<small>OS keyring unavailable. Newly saved credentials last only for this session.</small>")
            _sec_label.setWordWrap(True)
            conn_form.addRow(_sec_label)
        except ImportError:
            pass

        layout.addWidget(conn_group)

        # ── Downloads ────────────────────────────────────────
        dl_group = QGroupBox("Downloads (MWDB / Remote)")
        dl_form = QFormLayout(dl_group)

        dl_row = QHBoxLayout()
        self._dl_dir_input = QLineEdit(current_download_dir)
        self._dl_dir_input.setPlaceholderText("(not set — will prompt on first download)")
        dl_row.addWidget(self._dl_dir_input, 1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_download_dir)
        dl_row.addWidget(browse_btn)
        dl_form.addRow("Download Folder:", dl_row)

        self._auto_delete_check = QCheckBox(
            "Auto-delete downloaded files when hex editor closes")
        self._auto_delete_check.setChecked(current_auto_delete)
        self._auto_delete_check.setToolTip(
            "When enabled, files downloaded from MWDB are automatically\n"
            "deleted when the hex editor window that opened them is closed.")
        dl_form.addRow(self._auto_delete_check)

        clean_row = QHBoxLayout()
        self._clean_btn = QPushButton("Clean Download Folder Now")
        self._clean_btn.setToolTip("Delete all files in the download folder")
        self._clean_btn.clicked.connect(self._clean_downloads)
        clean_row.addWidget(self._clean_btn)
        self._clean_label = QLabel("")
        clean_row.addWidget(self._clean_label, 1)
        dl_form.addRow(clean_row)

        layout.addWidget(dl_group)

        # ── Buttons ──────────────────────────────────────────
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

    # ── Helpers ──────────────────────────────────────────────

    def _browse_api_ca(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose CA certificate", "", "Certificates (*.pem *.crt);;All files (*)")
        if path:
            self._api_ca_input.setText(path)

    def accept(self):
        from yaraxgui.network import tls_context
        try:
            if self._api_url_input.text().strip():
                self.api_server_url()
            tls_context(self.api_ca_file())
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Connection settings", str(exc))
            return
        super().accept()

    def api_https_enabled(self):
        return self._api_https_check.isChecked()

    def api_ca_file(self):
        return self._api_ca_input.text().strip()

    def _browse_download_dir(self):
        d = QFileDialog.getExistingDirectory(
            self, "Select Download Folder",
            self._dl_dir_input.text())
        if d:
            self._dl_dir_input.setText(d)

    def _clean_downloads(self):
        dl_dir = self._dl_dir_input.text().strip()
        if not dl_dir or not Path(dl_dir).is_dir():
            self._clean_label.setText("No valid folder set")
            return
        import shutil
        count = 0
        for item in Path(dl_dir).iterdir():
            try:
                if item.is_file():
                    item.unlink()
                    count += 1
                elif item.is_dir():
                    shutil.rmtree(item)
                    count += 1
            except Exception:
                pass
        self._clean_label.setText(f"Deleted {count} items")

    # ── Public getters ───────────────────────────────────────

    def ui_font_family(self) -> str:
        return self._ui_font_combo.currentFont().family()

    def ui_font_size(self) -> int:
        return self._ui_size_spin.value()

    def font_family(self) -> str:
        return self._font_combo.currentFont().family()

    def font_size(self) -> int:
        return self._size_spin.value()

    def tab_size(self) -> int:
        return self._tab_spin.value()

    def download_dir(self) -> str:
        return self._dl_dir_input.text().strip()

    def auto_delete_downloads(self) -> bool:
        return self._auto_delete_check.isChecked()

    def api_server_url(self) -> str:
        from yaraxgui.network import api_url
        value = self._api_url_input.text().strip()
        return api_url(value, lambda key, default: self.api_https_enabled()) if value else ""

    def api_server_key(self) -> str:
        return self._api_key_input.text().strip()

    def mwdb_url(self) -> str:
        return self._mwdb_url_input.text().strip()

    def mwdb_token(self) -> str:
        return self._mwdb_token_input.text().strip()
