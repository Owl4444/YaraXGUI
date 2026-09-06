"""Process-isolated Hex/Text/Regex search with bounded virtual results."""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
    QWidget, QLabel, QLineEdit, QCheckBox, QPushButton, QProgressBar)
from .hex_data_buffer import HexDataBuffer
from .analysis_controller import AnalysisController
from .analysis_results import ResultsModel, results_table


class HexSearchDialog(QDialog):
    """Non-modal search dialog with Hex/Text/Regex tabs."""

    navigate_requested = Signal(int, int)  # offset, length

    def __init__(self, buffer: HexDataBuffer, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Find")
        self.setMinimumSize(500, 400)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)

        self._buffer = buffer
        self._last_offset = -1

        layout = QVBoxLayout(self)

        # Tabs
        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # Hex tab
        hex_tab = QWidget()
        hl = QVBoxLayout(hex_tab)
        self._hex_input = QLineEdit()
        self._hex_input.setPlaceholderText("e.g. 4D 5A ?? 00 03")
        self._hex_input.returnPressed.connect(self._find_next_hex)
        hl.addWidget(QLabel("Hex Pattern (use ?? for wildcards):"))
        hl.addWidget(self._hex_input)
        hl.addStretch()
        self._tabs.addTab(hex_tab, "Hex")

        # Text tab
        text_tab = QWidget()
        tl = QVBoxLayout(text_tab)
        self._text_input = QLineEdit()
        self._text_input.setPlaceholderText("Search text...")
        self._text_input.returnPressed.connect(self._find_next_text)
        tl.addWidget(QLabel("Text:"))
        tl.addWidget(self._text_input)
        opt_row = QHBoxLayout()
        self._case_cb = QCheckBox("Case sensitive")
        self._case_cb.setChecked(True)
        opt_row.addWidget(self._case_cb)
        self._enc_utf16 = QCheckBox("UTF-16LE")
        opt_row.addWidget(self._enc_utf16)
        opt_row.addStretch()
        tl.addLayout(opt_row)
        tl.addStretch()
        self._tabs.addTab(text_tab, "Text")

        # Regex tab
        regex_tab = QWidget()
        rl = QVBoxLayout(regex_tab)
        self._regex_input = QLineEdit()
        self._regex_input.setPlaceholderText(r"e.g. \x4D\x5A..\x00")
        self._regex_input.returnPressed.connect(self._find_next_regex)
        rl.addWidget(QLabel("Regex (on raw bytes, latin-1):"))
        rl.addWidget(self._regex_input)
        rl.addStretch()
        self._tabs.addTab(regex_tab, "Regex")

        # Buttons
        btn_row = QHBoxLayout()
        self._btn_prev = QPushButton("Find Previous")
        self._btn_prev.clicked.connect(self._find_prev)
        btn_row.addWidget(self._btn_prev)
        self._btn_next = QPushButton("Find Next")
        self._btn_next.setDefault(True)
        self._btn_next.clicked.connect(self._find_next)
        btn_row.addWidget(self._btn_next)
        self._btn_all = QPushButton("Find All")
        self._btn_all.clicked.connect(self._find_all)
        btn_row.addWidget(self._btn_all)
        self._btn_cancel = QPushButton('Cancel')
        self._btn_cancel.setEnabled(False)
        btn_row.addWidget(self._btn_cancel)
        layout.addLayout(btn_row)

        # Progress
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        layout.addWidget(self._progress)

        self._model = ResultsModel(self)
        self._results_table = results_table(self._model)
        self._results_table.hideColumn(2)
        self._results_table.doubleClicked.connect(self._on_result_double_click)
        layout.addWidget(self._results_table)
        self._status = QLabel('')
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        self._controller = AnalysisController(self._model, self)
        self._controller.set_buffer(buffer)
        self._controller.status.connect(self._status.setText)
        self._controller.progress.connect(self._progress.setValue)
        self._controller.changed.connect(self._busy)
        self._btn_cancel.clicked.connect(self._controller.cancel)
        self._mode = 'all'
        self._tabs.currentChanged.connect(self._query_changed)
        for edit in (self._hex_input, self._text_input, self._regex_input):
            edit.textChanged.connect(self._query_changed)
        for checkbox in (self._case_cb, self._enc_utf16):
            checkbox.toggled.connect(self._query_changed)

    def set_buffer(self, buffer):
        self._buffer = buffer
        self._last_offset = -1
        self._controller.set_buffer(buffer)

    def _query_changed(self, *_args):
        self._controller.close()
        self._model.clear()
        self._last_offset = -1

    def _busy(self, running):
        for button in (self._btn_prev, self._btn_next, self._btn_all):
            button.setEnabled(not running)
        self._btn_cancel.setEnabled(running)
        self._progress.setVisible(running)
        if running:
            self._progress.setValue(0)
        elif (self._mode != 'all' and self._model.rows
              and not self._controller._cancelled):
            row = self._model.rows[0]
            self._last_offset = row[0]
            self.navigate_requested.emit(row[0], row[1])

    def _start(self, mode):
        kind = ('hex', 'text', 'regex')[self._tabs.currentIndex()]
        edit = (self._hex_input, self._text_input, self._regex_input)[self._tabs.currentIndex()]
        spec = dict(kind=kind, pattern=edit.text(), mode=mode,
                    encoding='utf-16-le' if self._enc_utf16.isChecked() else 'utf-8',
                    case_sensitive=self._case_cb.isChecked(),
                    start=(self._last_offset + 1 if mode == 'next' else
                           self._last_offset if self._last_offset >= 0 else self._buffer.size()))
        # Compilation is done in the child as well; syntax checking here is
        # intentionally avoided because even a huge regex can be expensive.
        if not spec['pattern']:
            self._status.setText('Enter a search pattern first')
            return
        self._mode = mode
        self._controller.start(spec)

    def _find_next(self):
        self._start('next')

    def _find_prev(self):
        self._start('previous')

    def _find_next_hex(self):
        self._tabs.setCurrentIndex(0)
        self._find_next()

    def _find_next_text(self):
        self._tabs.setCurrentIndex(1)
        self._find_next()

    def _find_next_regex(self):
        self._tabs.setCurrentIndex(2)
        self._find_next()

    def _find_all(self):
        self._start('all')

    def _on_result_double_click(self, index):
        if index.isValid():
            row = self._model.rows[self._model.visible[index.row()]]
            self._last_offset = row[0]
            self.navigate_requested.emit(row[0], row[1])

    def shutdown(self):
        self._controller.close()

    def reject(self):
        self.shutdown()
        super().reject()

    def closeEvent(self, event):
        self.shutdown()
        super().closeEvent(event)
