"""Bounded, process-isolated string extraction and virtual results display."""
from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QSpinBox, QCheckBox, QPushButton, QProgressBar, QMenu, QDialog, QPlainTextEdit)
from .analysis_controller import AnalysisController
from .analysis_results import ResultsModel, results_table
from .analysis_worker import MAX_RESULTS


class StringResultsWidget(QWidget):
    navigate_requested = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._buffer = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        settings = QHBoxLayout()
        settings.addWidget(QLabel('Min length:'))
        self._min_spin = QSpinBox()
        self._min_spin.setRange(2, 256)
        self._min_spin.setValue(4)
        settings.addWidget(self._min_spin)
        self._ascii_cb = QCheckBox('ASCII')
        self._ascii_cb.setChecked(True)
        settings.addWidget(self._ascii_cb)
        self._unicode_cb = QCheckBox('UTF-16LE')
        self._unicode_cb.setChecked(True)
        self._unicode_cb.setToolTip('Printable ASCII characters and CR/LF encoded as UTF-16LE; both byte alignments')
        settings.addWidget(self._unicode_cb)
        self._extract_btn = QPushButton('Extract')
        self._extract_btn.clicked.connect(self._on_extract)
        settings.addWidget(self._extract_btn)
        self._cancel_btn = QPushButton('Cancel')
        self._cancel_btn.setEnabled(False)
        settings.addWidget(self._cancel_btn)
        from yaraxgui.scanning.search_filter import DebouncedSearchBar
        self._filter_bar = DebouncedSearchBar('Filter previews, offsets or encoding…', self)
        settings.addWidget(self._filter_bar)
        layout.addLayout(settings)
        self._progress = QProgressBar()
        self._progress.setFixedHeight(16)
        self._progress.hide()
        layout.addWidget(self._progress)
        self._model = ResultsModel(self)
        self._table = results_table(self._model)
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self._table)
        self._status = QLabel('')
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        self._controller = AnalysisController(self._model, self)
        self._controller.changed.connect(self._busy)
        self._controller.status.connect(self._status.setText)
        self._controller.progress.connect(self._progress.setValue)
        self._model.filtering_changed.connect(
            lambda running: self._cancel_btn.setEnabled(running or self._controller.job is not None))
        self._cancel_btn.clicked.connect(self._on_cancel)
        self._filter_bar.debounced_text_changed.connect(self._apply_filter)

    def set_buffer(self, buffer):
        self._buffer = buffer
        self._controller.set_buffer(buffer)

    def _busy(self, running):
        self._extract_btn.setEnabled(not running)
        self._cancel_btn.setEnabled(running or self._model._timer.isActive())
        self._progress.setVisible(running)
        if running:
            self._progress.setValue(0)

    def _on_extract(self):
        if not self._ascii_cb.isChecked() and not self._unicode_cb.isChecked():
            self._status.setText('Select ASCII or UTF-16LE')
            return
        self._controller.start(dict(kind='strings', min_length=self._min_spin.value(),
            ascii=self._ascii_cb.isChecked(), unicode=self._unicode_cb.isChecked()))

    def _on_cancel(self):
        filtering = self._model._timer.isActive()
        self._controller.cancel()
        if filtering and self._controller.job is None:
            self._status.setText('Filtering cancelled — previous results retained')
        self._cancel_btn.setEnabled(False)

    def _on_double_click(self, index):
        if index.isValid():
            row = self._model.rows[self._model.visible[index.row()]]
            self.navigate_requested.emit(row[0], row[1])

    def _apply_filter(self, text):
        self._model.filter(text)
        self._cancel_btn.setEnabled(True)

    def _context_menu(self, position):
        index = self._table.indexAt(position)
        if not index.isValid():
            return
        menu = QMenu(self)
        view = menu.addAction('View string…')
        if menu.exec(self._table.viewport().mapToGlobal(position)) != view:
            return
        row = self._model.rows[self._model.visible[index.row()]]
        dialog = QDialog(self)
        dialog.setWindowTitle(f'String at 0x{row[0]:X}')
        dialog.resize(750, 450)
        layout = QVBoxLayout(dialog)
        limit = 1024 * 1024
        if row[1] > limit:
            layout.addWidget(QLabel('Showing the first 1 MiB. Double-click the result to inspect the full byte range.'))
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        text.setPlainText(self._buffer.read(row[0], min(row[1], limit)).decode(
            'ascii' if row[2] == 'ASCII' else 'utf-16-le', errors='replace'))
        layout.addWidget(text)
        dialog.exec()

    def shutdown(self):
        self._controller.close()

    def closeEvent(self, event):
        self.shutdown()
        super().closeEvent(event)
