"""GUI adapters for recovery storage. All disk work runs outside the GUI thread."""
import json
import time
import weakref
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal, Qt
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QListWidget,
    QPushButton, QLabel, QMessageBox)
from yaraxgui.recovery.store import DraftRecord, IO_POOL, discard_entry, recoverable_entries, restore_hex

_DRAFTS = weakref.WeakSet()


class DraftRecovery(QObject):
    status_changed = Signal(str)

    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor
        self.record = None
        self.restored_entry = None
        self.error = ''
        self._setup_error = ''
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.capture)
        self._error_timer = QTimer(self)
        self._error_timer.setInterval(1000)
        self._error_timer.timeout.connect(self._check_error)
        self._error_timer.start()
        editor.textChanged.connect(self._changed)
        editor.document().modificationChanged.connect(self._modified)
        _DRAFTS.add(self)
        self._changed()

    def _changed(self):
        if self.editor.document().isModified() and not self._timer.isActive():
            units = self.editor.document().characterCount()
            self._timer.start(1000 if units <= 65536 else 3000 if units <= 1024*1024
                              else 5000 if units <= 16*1024*1024 else 10000)

    def _check_error(self):
        error = (self.record.error if self.record is not None else '') or self._setup_error
        if error != self.error:
            self.error = error
            self.status_changed.emit(error)
            if error:
                self.editor.language_status.emit('Recovery failed: ' + error)

    def _modified(self, modified):
        if modified:
            self._changed()
        else:
            self.discard()

    def capture(self):
        self._timer.stop()
        if not self.editor.document().isModified():
            return
        try:
            if self.record is None:
                self.record = DraftRecord()
                self.editor.destroyed.connect(self.record.finish)
            self._setup_error = ''
            self._check_error()
            cursor = self.editor.textCursor()
            self.record.submit(self.editor.toPlainText(), dict(
                source=self.editor._tab_source_path,
                title=Path(self.editor._tab_source_path).name if self.editor._tab_source_path else getattr(self.editor, '_tab_recovery_title', 'Untitled'),
                cursor=cursor.position()))
        except Exception as exc:
            self._setup_error = str(exc)
            self._check_error()

    def discard(self):
        self._timer.stop()
        self._setup_error = ''
        if self.record is not None:
            self.record.discard()
            self.record = None
        if self.restored_entry is not None:
            IO_POOL.submit(discard_entry, self.restored_entry)
            self.restored_entry = None
        self._check_error()


def flush_drafts():
    for draft in list(_DRAFTS):
        draft.capture()


class RecoveryDialog(QDialog):
    recovered = Signal(object, object, object)  # entry, metadata, text or recovered path

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle('Recover Unsaved Work')
        self.resize(720, 400)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel('Restore a separate copy. Your original files will not be overwritten.'))
        self._list = QListWidget()
        layout.addWidget(self._list)
        row = QHBoxLayout()
        self._restore = QPushButton('Restore selected')
        self._delete = QPushButton('Discard selected…')
        close = QPushButton('Keep for later / Close')
        for button in (self._restore, self._delete, close):
            row.addWidget(button)
        layout.addLayout(row)
        self._status = QLabel('')
        self._status.setWordWrap(True)
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._status)
        self._restore.clicked.connect(self._start_restore)
        self._delete.clicked.connect(self._discard)
        close.clicked.connect(self.close)
        self._future = None
        self._restored = set()
        self._list.currentRowChanged.connect(self._selection_changed)
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._poll)
        self.reload()

    def reload(self):
        self.entries = recoverable_entries()
        self._list.clear()
        for folder, meta in self.entries:
            date = time.strftime('%Y-%m-%d %H:%M', time.localtime(meta.get('updated', 0)))
            name = meta.get('source') or meta.get('title') or 'Untitled'
            self._list.addItem(f"[{meta['kind'].upper()}] {name} — {date}")
        self._restore.setEnabled(bool(self.entries))
        self._delete.setEnabled(bool(self.entries))
        if self.entries:
            self._list.setCurrentRow(0)
        else:
            self._status.setText('No recovery drafts from closed or crashed sessions.')

    def _selection_changed(self, index):
        available = (0 <= index < len(self.entries) and self._future is None
                     and self.entries[index][0] not in self._restored)
        self._restore.setEnabled(available)
        self._delete.setEnabled(available)

    def _start_restore(self):
        index = self._list.currentRow()
        if index < 0 or self._future is not None:
            return
        folder, metadata = self.entries[index]
        self._restoring = (folder, metadata)
        def load():
            return ((folder / 'draft.yar').read_text(encoding='utf-8')
                    if metadata['kind'] == 'yara' else restore_hex(folder))
        self._future = IO_POOL.submit(load)
        self._restore.setEnabled(False)
        self._delete.setEnabled(False)
        self._status.setText('Restoring a separate copy… You can close this dialog safely.')
        self._timer.start()

    def _poll(self):
        if not self._future.done():
            return
        self._timer.stop()
        future, self._future = self._future, None
        try:
            value = future.result()
            self.recovered.emit(*self._restoring, value)
            self._restored.add(self._restoring[0])
            self._status.setText('Restored. The original recovery data remains until you save or discard the recovered document.')
        except Exception as exc:
            self._status.setText(f'Recovery failed: {exc}. Recovery data has been retained.')
        self._selection_changed(self._list.currentRow())

    def _discard(self):
        index = self._list.currentRow()
        if index < 0 or self._future is not None:
            return
        if QMessageBox.question(self, 'Discard recovery copy?',
                'Permanently discard this recovery copy? Original files are unaffected.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        discard_entry(self.entries[index][0])
        self.reload()
