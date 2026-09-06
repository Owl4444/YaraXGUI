"""An editable picker whose dropdown supports substring search."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QCompleter


class SearchableComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.lineEdit().setPlaceholderText("Type to search operations…")
        self.lineEdit().setClearButtonEnabled(True)
        completion = self.completer()
        completion.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        completion.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completion.setFilterMode(Qt.MatchFlag.MatchContains)
        completion.setMaxVisibleItems(15)
        completion.activated[str].connect(self._accept_completion)

    def showPopup(self):
        # Use the completer popup rather than the native combo list: typing
        # after clicking the arrow then reaches the search field immediately.
        self.lineEdit().setFocus()
        self.lineEdit().selectAll()
        self.completer().setCompletionPrefix("")
        self.completer().complete()

    def hidePopup(self):
        self.completer().popup().hide()
        super().hidePopup()

    def selected_data(self):
        # Editable combos retain the previous currentIndex while a query is
        # typed. Never let Add silently insert that previous operation.
        index = self.findText(self.currentText().strip(), Qt.MatchFlag.MatchFixedString)
        return self.itemData(index) if index >= 0 else None

    def _accept_completion(self, text):
        index = self.findText(text, Qt.MatchFlag.MatchFixedString)
        if index >= 0 and self.itemData(index) is not None:
            self.setCurrentIndex(index)
            self.setEditText(self.itemText(index))
        self.hidePopup()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape and self.currentText() != self.itemText(self.currentIndex()):
            self.setEditText(self.itemText(self.currentIndex()))
            self.hidePopup()
            event.accept()
            return
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            # Choosing an operation must not activate the dialog's Apply button.
            popup = self.completer().popup()
            index = popup.currentIndex()
            if popup.isVisible() and index.isValid() and index.flags() & Qt.ItemFlag.ItemIsEnabled:
                self._accept_completion(index.data())
            elif self.selected_data() is not None:
                self._accept_completion(self.currentText().strip())
            event.accept()
            return
        super().keyPressEvent(event)
