# This Python file uses the following encoding: utf-8

"""
CheckableFsModel - QFileSystemModel with exclusion-based checking.

Provides a file system model where items start checked by default,
and users can uncheck items to exclude them from scanning.
"""

from pathlib import Path

from PySide6.QtCore import QModelIndex, Qt, Signal
from PySide6.QtWidgets import QFileSystemModel


class CheckableFsModel(QFileSystemModel):
    """
    QFileSystemModel with exclusion-based checking.

    INTUITIVE BEHAVIOR:
    1. Everything starts CHECKED by default (ready to scan)
    2. UNCHECK a folder -> folder + all children become unchecked
       - Adds only the folder to exclusion list (instant, no filesystem walk)
       - Children inherit the unchecked state from parent
       - During scan: entire folder tree is skipped
    3. CHECK a folder -> folder + all children become checked
       - Removes folder and any previously unchecked children from exclusion list
       - User can still individually uncheck specific children after this
       - During scan: folder is scanned, but individually unchecked children are skipped

    MEMORY EFFICIENT:
    - Only stores explicitly unchecked items (exceptions to the rule)
    - Children inherit parent's state automatically
    - Fast even for huge directories like C:\\
    """
    exclusionsChanged = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._unchecked: set[str] = set()  # Paths that are explicitly UNCHECKED
        try:
            self.setOption(QFileSystemModel.DontWatchForChanges, False)
        except Exception:
            pass

    def _normalize_path(self, path: str) -> str:
        """Normalize path for consistent comparison (resolve symlinks, fix separators)"""
        try:
            return str(Path(path).resolve())
        except:
            return path

    def flags(self, index: QModelIndex):
        f = super().flags(index)
        if index.column() == 0:
            f |= Qt.ItemIsUserCheckable
        return f

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if role == Qt.CheckStateRole and index.column() == 0:
            path = self._normalize_path(self.filePath(index))

            # Check if this item itself is explicitly unchecked
            if path in self._unchecked:
                return Qt.Unchecked

            # Check if any parent directory is unchecked
            # If parent is unchecked, children should be unchecked too
            try:
                p = Path(path)
                for parent in p.parents:
                    parent_str = self._normalize_path(str(parent))
                    if parent_str in self._unchecked:
                        return Qt.Unchecked
            except (ValueError, OSError):
                pass

            # Default is CHECKED
            return Qt.Checked
        return super().data(index, role)

    def setData(self, index: QModelIndex, value, role: int = Qt.EditRole):
        if role == Qt.CheckStateRole and index.column() == 0:
            path = self._normalize_path(self.filePath(index))
            if not path:
                return False

            state = Qt.CheckState(value)

            if state == Qt.Unchecked:
                # User UNCHECKED this item
                self._unchecked.add(path)

                # If it's a folder, update visible children for immediate visual feedback
                if self.isDir(index):
                    self._update_visible_children(index)

            else:
                # User CHECKED this item
                self._unchecked.discard(path)

                # If it's a folder, remove any descendants from exclusion list
                # This allows children to be checked when parent is checked
                if self.isDir(index):
                    self._remove_descendants_from_exclusions(path)
                    self._update_visible_children(index)

            # Emit signals to update UI
            self.dataChanged.emit(index, index, [Qt.CheckStateRole])
            self.exclusionsChanged.emit()

            return True
        return super().setData(index, value, role)

    def _remove_descendants_from_exclusions(self, dir_path: str):
        """
        Remove all descendants of dir_path from the exclusion list.
        When you check a folder, all children should be checked too.
        """
        dir_p = Path(dir_path)
        to_remove = set()

        # Find all exclusions that are children of this directory
        for excluded_path in self._unchecked:
            try:
                p = Path(excluded_path)
                # Check if this excluded path is under the directory we just checked
                if p != dir_p and p.is_relative_to(dir_p):
                    to_remove.add(excluded_path)
            except (ValueError, OSError):
                pass

        # Remove them all
        self._unchecked -= to_remove

    def _update_visible_children(self, parent_index: QModelIndex):
        """
        Update visual checkstate of all loaded children recursively.
        Forces a visual refresh so children immediately show the inherited state.
        """
        if not parent_index.isValid():
            return

        row_count = self.rowCount(parent_index)

        for row in range(row_count):
            child_index = self.index(row, 0, parent_index)
            if not child_index.isValid():
                continue

            # Emit dataChanged to trigger visual update
            self.dataChanged.emit(child_index, child_index, [Qt.CheckStateRole])

            # Recursively update all loaded descendants
            if self.isDir(child_index) and self.hasChildren(child_index):
                # Only recurse if children are loaded
                if self.rowCount(child_index) > 0:
                    self._update_visible_children(child_index)

    def get_exclusion_list(self) -> list[str]:
        """Get list of excluded paths (what NOT to scan)"""
        return sorted(self._unchecked)

    def is_excluded(self, file_path: Path) -> bool:
        """
        Check if a file should be excluded from scanning.
        Returns True if the file or any of its parents are in the exclusion list.
        """
        file_str = self._normalize_path(str(file_path))

        # Check if file itself is excluded
        if file_str in self._unchecked:
            return True

        # Check if any parent directory is excluded
        for parent in file_path.parents:
            parent_str = self._normalize_path(str(parent))
            if parent_str in self._unchecked:
                return True

        return False

    def has_exclusions(self) -> bool:
        """Check if any items are excluded"""
        return bool(self._unchecked)
