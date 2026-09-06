"""Virtual results table and cancellable incremental filtering."""
import time
from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer, Signal
from PySide6.QtWidgets import QTableView, QAbstractItemView, QHeaderView


class ResultsModel(QAbstractTableModel):
    filtering_changed = Signal(bool)
    HEADERS = ('Offset', 'Length', 'Encoding', 'Preview')

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self.visible = []
        self.query = ''
        self._filtered = []
        self._filter_index = 0
        self._timer = QTimer(self)
        self._timer.setInterval(0)
        self._timer.timeout.connect(self._filter_step)

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.visible)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else 4

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self.visible):
            return None
        row = self.rows[self.visible[index.row()]]
        if role == Qt.ItemDataRole.DisplayRole:
            if index.column() == 0:
                return f'0x{row[0]:08X}'
            if index.column() == 3:
                truncated = row[1] > len(row[3]) * (2 if row[2] == 'UTF-16LE' else 1)
                return row[3] + ('…' if truncated and row[2] != 'Bytes' else '')
            return str(row[index.column()])
        if role == Qt.ItemDataRole.ToolTipRole:
            return 'Double-click to inspect the full byte range in the hex view'

    def clear(self):
        self._timer.stop()
        self.filtering_changed.emit(False)
        self.beginResetModel()
        self.rows = []
        self.visible = []
        self._filtered = []
        self.endResetModel()

    def append(self, rows):
        start = len(self.rows)
        self.rows.extend(rows)
        if self._timer.isActive():
            return  # The filter consumes newly appended rows too.
        indices = [start+i for i, row in enumerate(rows) if self._matches(row)]
        if indices:
            first = len(self.visible)
            self.beginInsertRows(QModelIndex(), first, first+len(indices)-1)
            self.visible.extend(indices)
            self.endInsertRows()

    def _matches(self, row):
        return (not self.query or self.query in row[3].lower() or
                self.query in row[2].lower() or self.query in f'0x{row[0]:08x}' or
                self.query in str(row[1]))

    def filter(self, text):
        self.query = text.lower()
        self._filtered = []
        self._filter_index = 0
        self._timer.start()
        self.filtering_changed.emit(True)

    def cancel_filter(self):
        self._timer.stop()
        self._filtered = []
        self.filtering_changed.emit(False)

    def _filter_step(self):
        deadline = time.monotonic() + .004
        while self._filter_index < len(self.rows) and time.monotonic() < deadline:
            index = self._filter_index
            if self._matches(self.rows[index]):
                self._filtered.append(index)
            self._filter_index += 1
        if self._filter_index == len(self.rows):
            self._timer.stop()
            self.beginResetModel()
            self.visible = self._filtered
            self._filtered = []
            self.endResetModel()
            self.filtering_changed.emit(False)


def results_table(model):
    table = QTableView()
    table.setModel(model)
    table.setWordWrap(False)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.verticalHeader().hide()
    table.verticalHeader().setDefaultSectionSize(22)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    table.horizontalHeader().setStretchLastSection(True)
    for column, width in enumerate((130, 90, 95)):
        table.setColumnWidth(column, width)
    return table
