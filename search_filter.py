# This Python file uses the following encoding: utf-8

"""
Reusable search/filter components for scan result tables and trees.

Provides debounced search bars, proxy filter models, and helper functions
to inject filtering into existing QTableView, QTreeWidget, and QTableWidget layouts.
"""

from PySide6.QtCore import QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtWidgets import QLineEdit, QVBoxLayout, QWidget


class DebouncedSearchBar(QLineEdit):
    """QLineEdit that emits debounced_text_changed after 300ms idle."""

    debounced_text_changed = Signal(str)

    def __init__(self, placeholder="Filter...", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(True)
        self.setFixedHeight(24)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(300)
        self._timer.timeout.connect(self._emit_text)
        self.textChanged.connect(self._restart_timer)

    def _restart_timer(self):
        self._timer.start()

    def _emit_text(self):
        self.debounced_text_changed.emit(self.text())

    def clear_filter(self):
        self.clear()


class MultiColumnFilterProxy(QSortFilterProxyModel):
    """Proxy model that filters rows if ANY column contains the filter text (case-insensitive)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_text = ""

    def set_filter_text(self, text: str):
        self._filter_text = text.lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if not self._filter_text:
            return True
        model = self.sourceModel()
        for col in range(model.columnCount()):
            index = model.index(source_row, col, source_parent)
            data = model.data(index, Qt.ItemDataRole.DisplayRole)
            if data and self._filter_text in str(data).lower():
                return True
        return False


def filter_tree_widget(tree, text: str):
    """Hide/show QTreeWidget items based on text match.

    - Parent visible if it matches OR any child matches.
    - If parent matches, all children are shown.
    - Empty text shows everything.
    """
    text = text.lower()
    for i in range(tree.topLevelItemCount()):
        parent = tree.topLevelItem(i)
        if not text:
            parent.setHidden(False)
            for j in range(parent.childCount()):
                parent.child(j).setHidden(False)
            continue

        parent_text = " ".join(parent.text(c) for c in range(parent.columnCount())).lower()
        parent_matches = text in parent_text

        if parent_matches:
            parent.setHidden(False)
            for j in range(parent.childCount()):
                parent.child(j).setHidden(False)
        else:
            any_child = False
            for j in range(parent.childCount()):
                child = parent.child(j)
                child_text = " ".join(child.text(c) for c in range(child.columnCount())).lower()
                if text in child_text:
                    child.setHidden(False)
                    any_child = True
                else:
                    child.setHidden(True)
            parent.setHidden(not any_child)


def filter_table_widget(table, text: str):
    """Hide/show QTableWidget rows based on text match across all columns."""
    text = text.lower()
    for row in range(table.rowCount()):
        if not text:
            table.setRowHidden(row, False)
            continue
        visible = False
        for col in range(table.columnCount()):
            item = table.item(row, col)
            if item and text in item.text().lower():
                visible = True
                break
        table.setRowHidden(row, not visible)


def inject_search_bar(layout, widget, placeholder="Filter..."):
    """Replace widget in its QHBoxLayout with a VBox container holding a search bar + widget.

    Returns the DebouncedSearchBar instance.
    """
    idx = layout.indexOf(widget)
    if idx < 0:
        return None

    layout.removeWidget(widget)

    container = QWidget()
    vbox = QVBoxLayout(container)
    vbox.setContentsMargins(0, 0, 0, 0)
    vbox.setSpacing(2)

    search_bar = DebouncedSearchBar(placeholder, container)
    vbox.addWidget(search_bar)
    vbox.addWidget(widget)

    layout.insertWidget(idx, container)
    return search_bar
