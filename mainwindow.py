# This Python file uses the following encoding: utf-8

"""
YaraXGUI - A GUI application for YARA-X rule scanning and analysis.

Usage:
    pyside6-uic form.ui -o ui_form.py
"""

# Standard library imports
import hashlib
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

# Third-party imports
from PySide6.QtCore import QDir, QModelIndex, QTimer, Qt, Signal
from PySide6.QtGui import (QIcon, QPainter, QPen, QPixmap, QStandardItem,
                           QStandardItemModel, QTextCursor)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QFileDialog,
                               QFileSystemModel, QHeaderView, QListWidgetItem,
                               QMainWindow, QMessageBox, QTreeView,
                               QTreeWidgetItem)

# Local imports
from themes import theme_manager
from ui_form import Ui_MainWindow
from yara_highlighter import YaraHighlighter

# Check if yara_x is available
try:
    import yara_x
    YARA_X_AVAILABLE = True
except ImportError:
    YARA_X_AVAILABLE = False

# Check if yaraast is available
try:
    import yaraast
    from yaraast.parser.better_parser import Parser
    from yaraast.codegen import CodeGenerator
    YARAAST_AVAILABLE = True
except ImportError:
    YARAAST_AVAILABLE = False


class CheckableFsModel(QFileSystemModel):
    """
    QFileSystemModel with exclusion-based checking.

    INTUITIVE BEHAVIOR:
    1. Everything starts CHECKED by default (ready to scan)
    2. UNCHECK a folder → folder + all children become unchecked
       - Adds only the folder to exclusion list (instant, no filesystem walk)
       - Children inherit the unchecked state from parent
       - During scan: entire folder tree is skipped
    3. CHECK a folder → folder + all children become checked
       - Removes folder and any previously unchecked children from exclusion list
       - User can still individually uncheck specific children after this
       - During scan: folder is scanned, but individually unchecked children are skipped

    MEMORY EFFICIENT:
    - Only stores explicitly unchecked items (exceptions to the rule)
    - Children inherit parent's state automatically
    - Fast even for huge directories like C:\
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


class MainWindow(QMainWindow):
    """
    Main application window for YaraXGUI.
    
    Provides a graphical interface for YARA-X rule scanning and analysis,
    including file selection, rule editing with syntax highlighting,
    compilation, scanning, and results visualization.
    
    Features:
    - File system browser with selective scanning
    - YARA rule editor with syntax highlighting
    - Real-time compilation and validation
    - Comprehensive scan results with multiple views
    - Theme support (light/dark)
    - AST-based formatting and syntax validation (when yaraast is available)
    """
    
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Syntax highlighter (will be updated with theme later)
        self.highlighter = YaraHighlighter(self.ui.te_yara_editor.document())
        
        # Optimize text editor for better performance with large files
        self.optimize_text_editor()
        
        # Enable line numbers in YARA editor
        self.setup_line_numbers()

    def optimize_text_editor(self):
        """Optimize the text editor for better performance with large files."""
        try:
            # Optimize document layout for better scrolling performance
            document = self.ui.te_yara_editor.document()
            
            # Enable document layout optimization for large documents
            # This helps with scrollbar performance when dealing with lots of text
            document.setDocumentMargin(4)  # Smaller margin for better performance
            
            # Set line wrap mode for better performance with large files
            # NoWrap mode generally performs better with very large text
            self.ui.te_yara_editor.setLineWrapMode(self.ui.te_yara_editor.LineWrapMode.NoWrap)
            
            # Set scroll bar policies to only show when needed
            from PySide6.QtCore import Qt
            self.ui.te_yara_editor.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            self.ui.te_yara_editor.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            
            # Configure scrollbar for better dragging behavior
            vertical_scrollbar = self.ui.te_yara_editor.verticalScrollBar()
            if vertical_scrollbar:
                # Set single step (arrow click) to 3 lines
                vertical_scrollbar.setSingleStep(3)
                # Set page step (page up/down or clicking in scrollbar track) to visible area
                vertical_scrollbar.setPageStep(20)
                # Enable tracking for smooth dragging
                vertical_scrollbar.setTracking(True)
            
            # Configure horizontal scrollbar similarly
            horizontal_scrollbar = self.ui.te_yara_editor.horizontalScrollBar()
            if horizontal_scrollbar:
                horizontal_scrollbar.setSingleStep(10)
                horizontal_scrollbar.setPageStep(50)
                horizontal_scrollbar.setTracking(True)
            
            # Make scrollbars more visible and draggable
            # Use a simpler style that ensures drag functionality works
            self.ui.te_yara_editor.setStyleSheet("""
                QTextEdit {
                    border: 1px solid #3d3d3d;
                }
                QScrollBar:vertical {
                    background-color: #2d2d2d;
                    width: 18px;
                    border: none;
                }
                QScrollBar::handle:vertical {
                    background-color: #606060;
                    min-height: 30px;
                    border-radius: 9px;
                    margin: 2px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #707070;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #808080;
                }
                QScrollBar::add-line:vertical {
                    height: 0px;
                }
                QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """)
            
            # Force refresh of scrollbar geometry
            self.ui.te_yara_editor.verticalScrollBar().update()
            
            # Ensure the scrollbar is enabled and interactive
            vertical_scrollbar = self.ui.te_yara_editor.verticalScrollBar()
            if vertical_scrollbar:
                vertical_scrollbar.setEnabled(True)
                vertical_scrollbar.show()
                # Make sure mouse tracking is enabled for proper interaction
                vertical_scrollbar.setMouseTracking(True)
            
        except Exception as e:
            print(f"Warning: Could not optimize text editor: {e}")

        # Invalidate compiled rules when editor text changes
        self.ui.te_yara_editor.textChanged.connect(self.on_yara_text_changed)

        # File system model
        self.fs_model = CheckableFsModel(self)
        self.fs_model.setFilter(QDir.AllEntries | QDir.NoDotAndDotDot)
        self.fs_model.setReadOnly(True)
        # Don't set any root path - tree will be empty until user selects a directory

        # QTreeView
        self.fs_view = QTreeView(self.ui.tab_scan_dir)
        self.fs_view.setModel(self.fs_model)  # Connect model but don't set root path yet
        self.fs_view.setAlternatingRowColors(True)
        self.fs_view.setUniformRowHeights(True)
        self.fs_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.fs_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.fs_view.setSortingEnabled(True)
        self.fs_view.sortByColumn(0, Qt.AscendingOrder)

        # Set an invalid root index so tree shows nothing until directory is selected
        self.fs_view.setRootIndex(QModelIndex())

        header = self.fs_view.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        # Replace treeWidget with fs_view in the splitter
        self.ui.treeWidget.setVisible(False)  # Hide original immediately
        
        # QSplitter.replaceWidget requires an index, not the widget reference
        # The treeWidget should be the first widget (index 0) in splitter_3
        self.ui.splitter_3.replaceWidget(0, self.fs_view)
        self.ui.treeWidget.deleteLater()
        self.fs_view.setVisible(True)  # Ensure our view is visible
        self.fs_view.show()  # Show it explicitly

        # Connect to expansion events to update children's checkboxes on-demand
        self.fs_view.expanded.connect(self.on_tree_expanded)

        # Setup
        self.last_dir = str(Path.home())
        self.scan_root: Path | None = None
        self.compiled_rules = None  # Store compiled YARA rules
        
        # Flag to prevent recursive selection updates
        self._updating_selection = False
        
        # Scan results data
        self.scan_hits = []  # List of hit file data
        self.scan_misses = []  # List of miss file data
        self.misses_loaded = False  # Track if misses are loaded
        
        # Setup scan results UI
        self.setup_scan_results_ui()
        
        # Configure built-in splitters from UI form
        self.configure_builtin_splitters()

        # Connect buttons
        self.ui.pb_browse_yara.clicked.connect(self.on_browse_yara)
        self.ui.pb_select_scan_dir.clicked.connect(self.on_select_scan_dir)
        self.ui.pb_save_rule.clicked.connect(self.on_save_rule)
        self.ui.pb_reset.clicked.connect(self.on_reset)
        self.ui.pb_format_yara.clicked.connect(self.on_format_yara)
        self.ui.pb_scan.clicked.connect(self.on_scan)

        # Setup keyboard shortcuts
        self.setup_keyboard_shortcuts()

        # Update list when exclusions change (debounced)
        self.update_timer = QTimer()
        self.update_timer.setSingleShot(True)
        self.update_timer.setInterval(100)
        self.update_timer.timeout.connect(self.update_exclusion_list)

        self.fs_model.exclusionsChanged.connect(lambda: self.update_timer.start())

        # ListWidget
        self.ui.listWidget.setUniformItemSizes(True)
        self.ui.listWidget.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)

        # Set initial helpful message
        self.ui.tb_compilation_output.setHtml(
            '<span style="color: gray;"><b>Ready to scan</b></span><br><br>'
            '<b>Steps to get started:</b><br>'
            '1. Load or write YARA rules in the editor above<br>'
            '2. Click <b>"Select Scan Dir"</b> to choose what to scan<br>'
            '3. Click <b>"SCAN"</b> to start the scan<br>'
        )
        
        # Setup context menu for compilation output
        self.setup_compilation_output_context_menu()
        
        # Initialize theming system
        self.theme_manager = theme_manager
        self.setup_theming()
        self.load_theme_settings()

    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for the application"""
        from PySide6.QtGui import QShortcut, QKeySequence
        
        # Word wrap toggle: Ctrl+W
        self.wrap_shortcut = QShortcut(QKeySequence("Ctrl+W"), self)
        self.wrap_shortcut.activated.connect(self.toggle_word_wrap)
        
        # Track current word wrap state
        self.word_wrap_enabled = False  # Start with no wrap (performance mode)

    def toggle_word_wrap(self):
        """Toggle word wrap in the YARA editor with responsive line number updates"""
        from PySide6.QtWidgets import QTextEdit
        from PySide6.QtCore import QTimer
        from PySide6.QtGui import QTextCursor
        
        # Store current cursor position to restore it
        cursor = self.ui.te_yara_editor.textCursor()
        cursor_position = cursor.position()
        
        if self.word_wrap_enabled:
            # Disable word wrap
            self.ui.te_yara_editor.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
            self.word_wrap_enabled = False
            self.statusBar().showMessage("Word wrap disabled", 2000)
        else:
            # Enable word wrap
            self.ui.te_yara_editor.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
            self.word_wrap_enabled = True
            self.statusBar().showMessage("Word wrap enabled", 2000)
        
        # Force immediate and responsive updates
        if hasattr(self.ui.te_yara_editor, 'line_number_area'):
            # Update viewport margins
            self.ui.te_yara_editor.setViewportMargins(
                self.ui.te_yara_editor.line_number_area_width(), 0, 0, 0
            )
            
            # Force document layout update by triggering a relayout
            doc = self.ui.te_yara_editor.document()
            doc.setModified(doc.isModified())  # Trigger layout recalculation
            
            # Restore cursor position
            cursor.setPosition(cursor_position)
            self.ui.te_yara_editor.setTextCursor(cursor)
            
            # Multiple update passes for responsiveness
            def update_sequence():
                self.ui.te_yara_editor.line_number_area.update()
                self.ui.te_yara_editor.viewport().update()
                
            # Immediate update
            update_sequence()
            
            # Follow-up updates to ensure everything is synchronized
            QTimer.singleShot(10, update_sequence)
            QTimer.singleShot(50, update_sequence)
            QTimer.singleShot(100, lambda: self.ui.te_yara_editor.ensureCursorVisible())

    def refresh_word_wrap_display(self):
        """Force refresh of word wrap display and line numbers - can be called externally"""
        if hasattr(self.ui.te_yara_editor, 'line_number_area'):
            # Force document layout update by triggering a relayout
            doc = self.ui.te_yara_editor.document()
            doc.setModified(doc.isModified())  # Trigger layout recalculation
            
            # Update line number area
            self.ui.te_yara_editor.setViewportMargins(
                self.ui.te_yara_editor.line_number_area_width(), 0, 0, 0
            )
            
            # Multiple update passes for smooth transitions
            self.ui.te_yara_editor.line_number_area.update()
            self.ui.te_yara_editor.viewport().update()
            
            # Ensure cursor stays visible
            self.ui.te_yara_editor.ensureCursorVisible()

    def resizeEvent(self, event):
        """Handle main window resize to improve word wrap responsiveness"""
        super().resizeEvent(event)
        
        # If word wrap is enabled, refresh the display for better responsiveness
        if hasattr(self, 'word_wrap_enabled') and self.word_wrap_enabled:
            from PySide6.QtCore import QTimer
            # Small delay to let resize complete before refreshing
            QTimer.singleShot(10, self.refresh_word_wrap_display)

    def setup_compilation_output_context_menu(self):
        """Setup context menu for compilation output widget"""
        from PySide6.QtWidgets import QMenu
        from PySide6.QtCore import Qt
        
        # Enable context menu
        self.ui.tb_compilation_output.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ui.tb_compilation_output.customContextMenuRequested.connect(self.show_compilation_output_context_menu)
    
    def show_compilation_output_context_menu(self, position):
        """Show context menu for compilation output"""
        from PySide6.QtWidgets import QMenu
        from PySide6.QtGui import QAction
        
        menu = QMenu(self)
        
        # Clear Output action
        clear_action = QAction("Clear Output", self)
        clear_action.triggered.connect(self.clear_compilation_output)
        menu.addAction(clear_action)
        
        # Copy All action
        copy_action = QAction("Copy All Text", self)
        copy_action.triggered.connect(lambda: QApplication.clipboard().setText(self.ui.tb_compilation_output.toPlainText()))
        menu.addAction(copy_action)
        
        # Rule Info action (if yaraast is available)
        if YARAAST_AVAILABLE:
            menu.addSeparator()
            rule_info_action = QAction("Show Rule Info", self)
            rule_info_action.triggered.connect(self.show_rule_info)
            menu.addAction(rule_info_action)
        
        # Show menu at cursor position
        menu.exec(self.ui.tb_compilation_output.mapToGlobal(position))
    
    def clear_compilation_output(self):
        """Clear the compilation output and show ready message"""
        self.ui.tb_compilation_output.clear()
        self.ui.tb_compilation_output.setHtml(
            '<span style="color: gray;"><i>Output cleared - ready for new operations</i></span>'
        )
    
    def show_rule_info(self):
        """Show detailed YARA rule information using AST analysis"""
        text = self.ui.te_yara_editor.toPlainText()
        
        if not text.strip():
            self.ui.tb_compilation_output.setHtml(
                '<span style="color: orange;">⚠ No YARA rule to analyze.</span>'
            )
            return
        
        try:
            rule_info = self.get_yara_rule_info(text)
            
            # Display in compilation output with consistent monospace formatting
            formatted_code = self._format_code_html(rule_info, "gray")
            
            self.ui.tb_compilation_output.setHtml(
                '<span style="color: blue;"><b>📊 YARA Rule Analysis</b></span><br><br>' +
                formatted_code
            )
            
        except Exception as e:
            self.ui.tb_compilation_output.setHtml(
                '<span style="color: red;"><b>✗ Rule Analysis Failed</b></span><br><br>' +
                f'<span style="color: red;">Error: {str(e)}</span>'
            )

    def setup_scan_results_ui(self):
        """Setup models and connections for scan results"""
        from PySide6.QtWidgets import QHeaderView
        
        # Setup hits table model with compact styling
        self.hits_model = QStandardItemModel()
        self.hits_model.setHorizontalHeaderLabels(['File', 'Path'])
        self.ui.tv_file_hits.setModel(self.hits_model)
        self.ui.tv_file_hits.selectionModel().currentRowChanged.connect(self.on_hit_selected)
        
        # Selection highlighting will be applied by theme system
        
        self._make_table_compact(self.ui.tv_file_hits)
        
        # Configure hits table columns for full filename display
        hits_header = self.ui.tv_file_hits.horizontalHeader()
        hits_header.setStretchLastSection(True)  # Last column stretches to fill space
        hits_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # File column auto-size to content
        hits_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # Path column stretches
        hits_header.setDefaultSectionSize(150)  # Default column width
        hits_header.setMinimumSectionSize(80)  # Minimum column width
        # Enable word wrapping and better text handling
        self.ui.tv_file_hits.setWordWrap(False)  # Disable word wrap for better performance
        self.ui.tv_file_hits.setTextElideMode(Qt.TextElideMode.ElideMiddle)  # Elide in middle to show file extension
        
        # Setup misses table model (will be populated lazily)
        self.misses_model = QStandardItemModel()
        self.misses_model.setHorizontalHeaderLabels(['File', 'Path'])
        self.ui.tv_file_misses.setModel(self.misses_model)
        self._make_table_compact(self.ui.tv_file_misses)
        
        # Configure misses table columns for full filename display
        misses_header = self.ui.tv_file_misses.horizontalHeader()
        misses_header.setStretchLastSection(True)  # Last column stretches to fill space
        misses_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # File column auto-size to content
        misses_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # Path column stretches
        misses_header.setDefaultSectionSize(150)  # Default column width
        misses_header.setMinimumSectionSize(80)  # Minimum column width
        # Enable word wrapping and better text handling
        self.ui.tv_file_misses.setWordWrap(False)  # Disable word wrap for better performance
        self.ui.tv_file_misses.setTextElideMode(Qt.TextElideMode.ElideMiddle)  # Elide in middle to show file extension
        
        # Setup rule details model
        self.rule_details_model = QStandardItemModel()
        self.rule_details_model.setHorizontalHeaderLabels(['Property', 'Value'])
        self.ui.tv_rule_details.setModel(self.rule_details_model)
        self._make_table_compact(self.ui.tv_rule_details)
        
        # Configure rule details table columns
        rule_details_header = self.ui.tv_rule_details.horizontalHeader()
        rule_details_header.setStretchLastSection(True)  # Last column stretches to fill space
        rule_details_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)  # Property column user-resizable
        rule_details_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # Value column stretches
        rule_details_header.setDefaultSectionSize(150)  # Default column width
        rule_details_header.setMinimumSectionSize(80)  # Minimum column width
        # Set initial column widths
        self.ui.tv_rule_details.setColumnWidth(0, 150)  # Property column initial width
        
        # Setup similar files tree widget
        self.ui.tw_similar_files.setHeaderLabels(['File/Rule', 'Info'])
        self.ui.tw_similar_files.setAlternatingRowColors(True)
        self.ui.tw_similar_files.setRootIsDecorated(True)  # Show expand/collapse arrows
        self.ui.tw_similar_files.setItemsExpandable(True)
        
        # Connect double-click handler for cross-widget synchronization
        self.ui.tw_similar_files.itemDoubleClicked.connect(self.on_similar_file_double_clicked)
        
        # Make tree widget compact
        self._make_tree_compact(self.ui.tw_similar_files)
        
        # Setup similar tags tree widget (if it exists)
        if hasattr(self.ui, 'tw_similar_tags'):
            self.ui.tw_similar_tags.setHeaderLabels(['Tag/File', 'Details'])
            self.ui.tw_similar_tags.setAlternatingRowColors(True)
            self.ui.tw_similar_tags.setRootIsDecorated(True)  # Show expand/collapse arrows
            self.ui.tw_similar_tags.setItemsExpandable(True)
            
            # Connect double-click handler for cross-widget synchronization
            self.ui.tw_similar_tags.itemDoubleClicked.connect(self.on_similar_tag_double_clicked)
            
            # Make tree widget compact
            self._make_tree_compact(self.ui.tw_similar_tags)
        
        # Setup YARA match details tree widget in tabWidget_4 "All" tab
        self.setup_match_details_widget()
        
        # Connect tab change to lazy load misses
        self.ui.tabWidget_2.currentChanged.connect(self.on_results_tab_changed)

    def setup_match_details_widget(self):
        """Setup the YARA match details table widget in tabWidget_4"""
        from PySide6.QtWidgets import QHeaderView
        
        # Use the existing QTableWidget from the UI form and configure it
        self.tw_yara_match_details = self.ui.tw_yara_match_details
        
        # Set up table headers for comprehensive match details
        headers = ['File', 'Rule', 'Pattern ID', 'Offset', 'Data Preview', 'Hex Dump', 'Tag']
        self.tw_yara_match_details.setColumnCount(len(headers))
        self.tw_yara_match_details.setHorizontalHeaderLabels(headers)
        
        # Configure table appearance
        from PySide6.QtWidgets import QAbstractItemView
        self.tw_yara_match_details.setAlternatingRowColors(True)
        self.tw_yara_match_details.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tw_yara_match_details.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tw_yara_match_details.setSortingEnabled(True)
        
        # Configure column widths - make all headers adjustable
        header = self.tw_yara_match_details.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)  # All columns user-adjustable
        header.setStretchLastSection(True)  # Last column stretches to fill space
        
        # Set initial column widths
        self.tw_yara_match_details.setColumnWidth(0, 200)  # File
        self.tw_yara_match_details.setColumnWidth(1, 150)  # Rule
        self.tw_yara_match_details.setColumnWidth(2, 100)  # Pattern ID
        self.tw_yara_match_details.setColumnWidth(3, 100)  # Offset
        self.tw_yara_match_details.setColumnWidth(4, 250)  # Data Preview
        self.tw_yara_match_details.setColumnWidth(5, 200)  # Hex Dump
        self.tw_yara_match_details.setColumnWidth(6, 100)  # Tag
        
        # Make table compact
        self._make_table_compact(self.tw_yara_match_details)
        
        # Connect double-click to show detailed info
        self.tw_yara_match_details.cellDoubleClicked.connect(self.on_match_detail_double_clicked)
        
        # Update the tab text to be more descriptive
        all_tab_index = self.ui.tabWidget_4.indexOf(self.ui.tab)
        if all_tab_index >= 0:
            self.ui.tabWidget_4.setTabText(all_tab_index, "Match Details")


    def configure_builtin_splitters(self):
        """Configure the built-in splitters from the UI form"""
        # Configure the horizontal splitter (hits/misses vs rule details/similar files)
        if hasattr(self.ui, 'splitter'):
            # Set proportions (60% hits, 40% rule details)
            self.ui.splitter.setStretchFactor(0, 60)  # Hits/Misses tab
            self.ui.splitter.setStretchFactor(1, 40)  # Rule Details/Similar Files tab
            
            # Set minimum sizes to prevent panels from becoming too small
            self.ui.splitter.setChildrenCollapsible(False)  # Prevent complete collapse
            self.ui.tabWidget_2.setMinimumWidth(200)  # Min width for hits/misses
            self.ui.tabWidget_3.setMinimumWidth(250)  # Min width for rule details
        
        # Configure the main vertical splitter (results vs bottom tabs)
        if hasattr(self.ui, 'splitter_2'):
            # Set proportions (70% for results, 30% for bottom tabs)
            self.ui.splitter_2.setStretchFactor(0, 70)  # Results section (splitter)
            self.ui.splitter_2.setStretchFactor(1, 30)  # Bottom tabs (tabWidget_4)
            self.ui.splitter_2.setChildrenCollapsible(False)  # Prevent complete collapse
        
        # Configure the directory tree splitter
        if hasattr(self.ui, 'splitter_3'):
            # Set proportions (80% for tree, 20% for exclusion list)
            self.ui.splitter_3.setStretchFactor(0, 80)  # Directory tree
            self.ui.splitter_3.setStretchFactor(1, 20)  # Exclusion list
            self.ui.splitter_3.setChildrenCollapsible(False)  # Prevent complete collapse
            
            # Remove the restrictive maximum height on listWidget to allow more splitter movement
            self.ui.listWidget.setMaximumSize(16777215, 16777215)  # Remove height restriction

    def _make_table_compact(self, table_view):
        """Make table rows thin and compact without affecting layout"""
        from PySide6.QtWidgets import QHeaderView
        
        # ONLY set row heights - nothing else that might affect layout
        table_view.verticalHeader().setDefaultSectionSize(18)  # Thin rows
        table_view.verticalHeader().setMinimumSectionSize(16)
        table_view.verticalHeader().setMaximumSectionSize(20)  # Prevent fat rows
        
        # Hide row numbers to save space
        table_view.verticalHeader().setVisible(False)
    
        # Force uniform thin rows
        table_view.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        
        # Keep default behavior for everything else - no size policies or restrictions

    def _make_tree_compact(self, tree_widget):
        """Make tree widget compact with thin items"""
        
        # Set compact item height
        tree_widget.setUniformRowHeights(True)
        tree_widget.header().setDefaultSectionSize(100)
        tree_widget.header().setMinimumSectionSize(50)
        
        # Make items smaller
        font = tree_widget.font()
        font.setPointSize(max(8, font.pointSize() - 1))
        tree_widget.setFont(font)
        
        # Set compact indentation
        tree_widget.setIndentation(15)  # Smaller indent for child items

    def _apply_column_color(self, item, col_idx):
        """Apply column-specific background colors to table items"""
        from PySide6.QtGui import QColor
        
        # Get current theme colors
        theme = self.theme_manager.current_theme
        if not hasattr(theme.colors, 'column_file'):
            return  # Theme doesn't have column colors
            
        colors = theme.colors
        
        # Define column color mapping
        column_colors = [
            colors.column_file,      # 0: File
            colors.column_rule,      # 1: Rule  
            colors.column_pattern,   # 2: Pattern ID
            colors.column_offset,    # 3: Offset
            colors.column_data,      # 4: Data Preview
            colors.column_hex,       # 5: Hex Dump
            colors.table_background  # 6: Tags (fallback to normal)
        ]
        
        # Apply background color based on column
        if col_idx < len(column_colors):
            bg_color = QColor(column_colors[col_idx])
            item.setBackground(bg_color)

    def _force_thin_rows(self, table_view) -> None:
        """Force all existing rows to be thin"""
        if not table_view.model():
            return
        for row in range(table_view.model().rowCount()):
            table_view.setRowHeight(row, 20)

    # Utility Methods
    def _handle_error(self, error: Exception, context: str = "Operation") -> None:
        """
        Centralized error handling with consistent logging and user feedback.
        
        Args:
            error: The exception that occurred
            context: Description of the operation that failed
        """
        error_msg = f"{context} failed: {str(error)}"
        
        # Log to compilation output for user visibility
        self.ui.tb_compilation_output.append(
            f'<span style="color: red;">❌ {error_msg}</span>'
        )
        
        # Show in status bar for immediate feedback
        self.statusBar().showMessage(error_msg, 5000)
    
    def _show_compilation_error_dialog(self, error_msg: str) -> None:
        """
        Show compilation error dialog for immediate user notification.
        
        Args:
            error_msg: The compilation error message to display
        """
        from PySide6.QtWidgets import QMessageBox
        
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle("YARA Compilation Error")
        msg.setText("Failed to compile YARA rule")
        
        # Format the error message for better readability
        if len(error_msg) > 300:
            short_msg = error_msg[:300] + "..."
            msg.setInformativeText(f"Error: {short_msg}")
            msg.setDetailedText(error_msg)
        else:
            msg.setInformativeText(f"Error: {error_msg}")
        
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()
    
    def _format_code_html(self, code: str, color: str = "black") -> str:
        """
        Format code text for HTML display with proper monospace styling.
        
        Args:
            code: The code text to format
            color: Text color for the code
            
        Returns:
            HTML-formatted code with proper monospace styling
        """
        # Escape HTML characters
        import html
        escaped_code = html.escape(code)
        
        # Use proper monospace font family with fallbacks
        return (
            f'<pre style="'
            f'font-family: Consolas, \'Courier New\', Monaco, monospace; '
            f'color: {color}; '
            f'margin: 0; '
            f'padding: 0; '
            f'white-space: pre-wrap; '
            f'word-wrap: break-word;'
            f'">{escaped_code}</pre>'
        )

    def _setup_monospace_fonts(self) -> None:
        """Setup consistent monospace fonts across editor and compilation output"""
        from PySide6.QtGui import QFont
        
        # Get font settings from current theme
        theme = self.theme_manager.current_theme if hasattr(self, 'theme_manager') else None
        if theme:
            font_family = theme.editor_font_family
            font_size = theme.editor_font_size
        else:
            # Fallback values if theme not yet initialized
            font_family = "Consolas"
            font_size = 8  # Decreased default size for better readability
        
        # Create consistent monospace font with theme settings
        font = QFont(font_family, font_size)
        if not font.exactMatch():
            font = QFont("Courier New", font_size)
        if not font.exactMatch():
            font = QFont("Monaco", font_size)  # macOS fallback
        if not font.exactMatch():
            font = QFont("monospace", font_size)  # Generic fallback
            
        # Apply to YARA editor
        self.ui.te_yara_editor.setFont(font)
        
        # Apply to compilation output for consistent formatting
        self.ui.tb_compilation_output.setFont(font)

    def setup_line_numbers(self) -> None:
        """Setup proper line numbers for YARA editor like classic code editors"""
        from PySide6.QtWidgets import QWidget, QTextEdit
        from PySide6.QtCore import QRect, Qt, QSize
        from PySide6.QtGui import QColor, QPainter, QTextFormat, QFont
        
        # Setup fonts first
        self._setup_monospace_fonts()
        
        editor = self.ui.te_yara_editor
        
        # Configure tab settings for 2 spaces
        font_metrics = editor.fontMetrics()
        tab_width = 4 * font_metrics.horizontalAdvance(' ')  # 2 spaces worth of width
        editor.setTabStopDistance(tab_width)
        
        # Make sure cursor is visible
        editor.setCursorWidth(2)  # Make cursor thicker and more visible
        editor.ensureCursorVisible()
        
        class LineNumberArea(QWidget):
            def __init__(self, editor):
                super().__init__(editor)
                self.code_editor = editor

            def sizeHint(self):
                return QSize(self.code_editor.line_number_area_width(), 0)

            def paintEvent(self, event):
                self.code_editor.line_number_area_paint_event(event)

        def line_number_area_width():
            digits = 1
            count = max(1, editor.document().blockCount())
            while count >= 10:
                count //= 10  # Use integer division for cleaner calculation
                digits += 1
            
            # Dynamic padding based on font size for better scaling
            font_metrics = editor.fontMetrics()
            digit_width = font_metrics.horizontalAdvance('9')
            
            # Scale padding with font size: base padding + extra for larger fonts
            base_padding = 12
            font_size_padding = max(4, font_metrics.height() // 4)
            left_padding = base_padding + font_size_padding
            right_padding = 8 + font_size_padding // 2
            
            space = left_padding + (digit_width * digits) + right_padding
            return space

        def update_line_number_area_width():
            editor.setViewportMargins(line_number_area_width(), 0, 0, 0)

        def highlight_current_line():
            """Applies theme-aware background color to the current line."""
            extra_selections = []
            if not editor.isReadOnly():
                selection = QTextEdit.ExtraSelection()
                
                # Use theme-aware current line color
                if hasattr(self, 'theme_manager') and self.theme_manager.current_theme:
                    theme_color = self.theme_manager.current_theme.colors.editor_current_line
                    line_color = QColor(theme_color)
                else:
                    # Fallback to very subtle gray if no theme available
                    line_color = QColor(250, 250, 250)
                
                selection.format.setBackground(line_color)
                selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
                selection.cursor = editor.textCursor()
                selection.cursor.clearSelection()
                extra_selections.append(selection)
            editor.setExtraSelections(extra_selections)

        def update_line_number_area():
            # Simple update for QTextEdit
            editor.line_number_area.update()

        def line_number_area_paint_event(event):
            painter = QPainter(editor.line_number_area)
            try:
                # Use theme-aware colors
                from PySide6.QtWidgets import QApplication
                palette = QApplication.palette()
                
                # Background: slightly darker than base for contrast
                bg_color = palette.color(palette.ColorRole.Base)
                if bg_color.lightness() > 128:  # Light theme
                    # Make it slightly darker for light themes
                    line_bg = bg_color.darker(105)  # 5% darker
                    text_color = palette.color(palette.ColorRole.Text).lighter(150)  # Lighter text
                    current_line_color = QColor(240, 240, 240, 120)  # Very light gray with transparency
                else:  # Dark theme
                    # Make it slightly lighter for dark themes  
                    line_bg = bg_color.lighter(115)  # 15% lighter
                    text_color = palette.color(palette.ColorRole.Text).darker(150)  # Darker text
                    current_line_color = QColor(80, 80, 80, 120)  # Dark gray with transparency
                
                painter.fillRect(event.rect(), line_bg)

                # Simplified approach for QTextEdit - works reliably with word wrap
                doc = editor.document()
                width = editor.line_number_area.width()
                font_height = editor.fontMetrics().height()
                current_cursor_line = editor.textCursor().blockNumber()
                
                # Calculate visible area
                viewport_top = editor.verticalScrollBar().value()
                viewport_bottom = viewport_top + editor.viewport().height()
                
                # Start from the first block
                block = doc.firstBlock()
                block_number = 0
                y_position = 0
                
                while block.isValid():
                    if block.isVisible():
                        # Calculate block height - use document layout for accurate positioning
                        block_height = int(doc.documentLayout().blockBoundingRect(block).height())
                        
                        # Only paint if block is in visible area
                        if y_position + block_height >= viewport_top and y_position <= viewport_bottom:
                            # Calculate adjusted y position relative to viewport
                            adjusted_y = y_position - viewport_top
                            
                            # Check if this intersects with the paint event area
                            if (adjusted_y + block_height >= event.rect().top() and 
                                adjusted_y <= event.rect().bottom()):
                                
                                # Highlight current line block
                                if block_number == current_cursor_line:
                                    painter.fillRect(0, adjusted_y, width, block_height, current_line_color)
                                    painter.setPen(palette.color(palette.ColorRole.Text))
                                else:
                                    painter.setPen(text_color)
                                
                                # Check if word wrap is enabled
                                word_wrap_enabled = (hasattr(self, 'word_wrap_enabled') and 
                                                   getattr(self, 'word_wrap_enabled', False))
                                
                                number = str(block_number + 1)
                                right_margin = max(5, width // 10)
                                
                                # Position line number at the TOP of the text line, accounting for document margin
                                # The document has a margin that offsets the text, so we need to align with that
                                document_margin = doc.documentMargin()
                                text_top_y = adjusted_y + document_margin
                                
                                # Draw the line number aligned with the TOP of the text
                                painter.drawText(0, int(text_top_y), width - right_margin, font_height,
                                               Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop, number)
                                
                                # If word wrap is enabled and block spans multiple lines, add continuation indicators
                                if (word_wrap_enabled and block.layout() and block.layout().lineCount() > 1):
                                    painter.setPen(text_color.darker(150))  # Dimmer color for continuation
                                    layout = block.layout()
                                    for visual_line_idx in range(1, layout.lineCount()):
                                        line = layout.lineAt(visual_line_idx)
                                        # Position continuation indicator at top of wrapped line, accounting for document margin
                                        continuation_y = adjusted_y + line.y() + document_margin
                                        if continuation_y < adjusted_y + block_height + document_margin:  # Within block bounds
                                            painter.drawText(0, int(continuation_y), width - right_margin, font_height,
                                                           Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop, "∙")
                        
                        y_position += block_height
                        
                        # Early exit if we're past visible area
                        if y_position > viewport_bottom:
                            break
                    
                    block = block.next()
                    block_number += 1
            
            finally:
                # Ensure painter is properly ended
                painter.end()

        def resizeEvent(event):
            # Handle resize of editor to update line number area
            cr = editor.contentsRect()
            editor.line_number_area.setGeometry(QRect(cr.left(), cr.top(),
                                                    line_number_area_width(), cr.height()))

        def show_line_column():
            # Show line/column in status bar - word wrap aware
            cursor = editor.textCursor()
            
            # Get logical line (document block)
            logical_line = cursor.blockNumber() + 1
            col = cursor.columnNumber() + 1
            
            # Check if word wrap is enabled
            if hasattr(self, 'word_wrap_enabled') and self.word_wrap_enabled:
                # Calculate visual line when word wrap is enabled
                try:
                    block = cursor.block()
                    if block.isValid() and block.layout():
                        layout = block.layout()
                        # Find which line within the block the cursor is on
                        relative_pos = cursor.positionInBlock()
                        visual_line_in_block = layout.lineForTextPosition(relative_pos).lineNumber()
                        
                        # Count total visual lines up to current block
                        total_visual_lines = 0
                        current_block = editor.document().firstBlock()
                        
                        while current_block.isValid() and current_block.blockNumber() < logical_line - 1:
                            if current_block.layout():
                                total_visual_lines += current_block.layout().lineCount()
                            else:
                                total_visual_lines += 1  # Fallback for blocks without layout
                            current_block = current_block.next()
                        
                        # Add the line within current block
                        visual_line = total_visual_lines + visual_line_in_block + 1
                        
                        self.statusBar().showMessage(f"Line: {visual_line} (Block: {logical_line}), Column: {col}")
                    else:
                        # Fallback to logical line if layout is not available
                        self.statusBar().showMessage(f"Line: {logical_line}, Column: {col}")
                except Exception:
                    # Fallback to logical line on any error
                    self.statusBar().showMessage(f"Line: {logical_line}, Column: {col}")
            else:
                # Word wrap disabled - show logical line
                self.statusBar().showMessage(f"Line: {logical_line}, Column: {col}")

        # Add methods and properties to editor
        editor.line_number_area_width = line_number_area_width
        editor.line_number_area_paint_event = line_number_area_paint_event

        # Create line number area
        editor.line_number_area = LineNumberArea(editor)

        # Connect signals for dynamic updates
        editor.textChanged.connect(update_line_number_area_width)
        editor.textChanged.connect(update_line_number_area)
        editor.verticalScrollBar().valueChanged.connect(lambda: editor.line_number_area.update())
        editor.horizontalScrollBar().valueChanged.connect(lambda: editor.line_number_area.update())
        editor.cursorPositionChanged.connect(highlight_current_line)
        editor.cursorPositionChanged.connect(show_line_column)
        editor.cursorPositionChanged.connect(lambda: editor.line_number_area.update())  # Update for current line highlight
        
        # Additional responsive connections for word wrap changes
        def responsive_update():
            """More responsive update that handles layout changes"""
            update_line_number_area_width()
            update_line_number_area()
            # Force layout recalculation by triggering modification state
            doc = editor.document()
            doc.setModified(doc.isModified())
        
        # Update on font changes and theme changes
        def on_font_or_theme_change():
            update_line_number_area_width()
            editor.line_number_area.update()
        
        # Connect to application palette changes (theme switching)
        QApplication.instance().paletteChanged.connect(on_font_or_theme_change)
        
        # Connect to document layout changes for better word wrap responsiveness
        if hasattr(editor.document(), 'documentLayoutChanged'):
            editor.document().documentLayoutChanged.connect(responsive_update)
        
        # Override resize event
        original_resize = editor.resizeEvent
        def new_resize_event(event):
            if original_resize:
                original_resize(event)
            resizeEvent(event)
        editor.resizeEvent = new_resize_event

        # Initial setup
        update_line_number_area_width()
        highlight_current_line()
        show_line_column()
        
        # Make sure cursor blinks and is visible
        editor.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        editor.setTextInteractionFlags(Qt.TextInteractionFlag.TextEditorInteraction)

    def setup_theming(self):
        """Setup theming system and add theme selector to UI"""
        from PySide6.QtWidgets import QComboBox, QLabel, QHBoxLayout, QWidget, QSpacerItem, QSizePolicy
        
        # Create theme selector widget
        theme_widget = QWidget()
        theme_layout = QHBoxLayout(theme_widget)
        theme_layout.setContentsMargins(0, 0, 0, 0)
        
        # Add spacer to push theme selector to the right
        spacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        theme_layout.addItem(spacer)
        
        # Theme label
        theme_label = QLabel("Theme:")
        theme_layout.addWidget(theme_label)
        
        # Theme selector combo box
        self.theme_combo = QComboBox()
        available_themes = self.theme_manager.get_available_themes()
        for theme_name in available_themes.keys():
            self.theme_combo.addItem(theme_name)
        
        # Connect theme change
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        theme_layout.addWidget(self.theme_combo)
        
        # Add theme selector to status bar
        self.statusBar().addPermanentWidget(theme_widget)
    
    def load_theme_settings(self):
        """Load saved theme settings or apply default theme"""
        config_path = Path(__file__).parent / "config" / "settings.json"
        
        # Default to light theme
        current_theme = "Light"
        
        # Try to load saved theme preference
        try:
            if config_path.exists():
                import json
                with open(config_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                current_theme = settings.get('theme', 'Light')
        except Exception as e:
            print(f"Error loading theme settings: {e}")
        
        # Set theme in combo box and apply
        if current_theme in [self.theme_combo.itemText(i) for i in range(self.theme_combo.count())]:
            self.theme_combo.setCurrentText(current_theme)
        
        self.apply_theme(current_theme)
    
    def save_theme_settings(self, theme_name):
        """Save theme preference to config file"""
        config_path = Path(__file__).parent / "config" / "settings.json"
        
        try:
            # Load existing settings or create new
            settings = {}
            if config_path.exists():
                import json
                with open(config_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
            
            # Update theme setting
            settings['theme'] = theme_name
            
            # Save settings
            import json
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2)
                
        except Exception as e:
            print(f"Error saving theme settings: {e}")
    
    def on_theme_changed(self, theme_name):
        """Handle theme change from combo box"""
        if theme_name:
            self.apply_theme(theme_name)
            self.save_theme_settings(theme_name)
    
    def apply_theme(self, theme_name):
        """Apply the selected theme to the entire application"""
        # Get theme
        theme = self.theme_manager.get_theme(theme_name)
        self.theme_manager.set_current_theme(theme_name)
        
        # Generate and apply stylesheet
        stylesheet = self.theme_manager.generate_qss_stylesheet(theme)
        
        # Apply to application
        self.setStyleSheet(stylesheet)
        
        # Update specific widget styles that need theme-aware CSS
        self.update_themed_widgets(theme)
        
        # Update syntax highlighter if needed
        if hasattr(self, 'highlighter') and self.highlighter:
            self.highlighter.update_theme(theme)
    
    def update_themed_widgets(self, theme):
        """Update widgets that need specific theme-aware styling"""
        colors = theme.colors
        
        # Update persistent selection highlighting for hits table
        hits_selection_style = f"""
            QTableView::item:selected {{
                background-color: {colors.selection_background};
                color: {colors.selection_text};
            }}
            QTableView::item:selected:!active {{
                background-color: {colors.selection_inactive};
                color: {colors.selection_text};
            }}
        """
        
        if hasattr(self.ui, 'tv_file_hits'):
            current_style = self.ui.tv_file_hits.styleSheet()
            # Replace existing selection styles or add new ones
            if "QTableView::item:selected" in current_style:
                # Remove old selection styles and add new ones
                import re
                pattern = r'QTableView::item:selected[^}]*}[^}]*}'
                current_style = re.sub(pattern, '', current_style)
            
            self.ui.tv_file_hits.setStyleSheet(current_style + hits_selection_style)
        
        # Update similar files tree selection styling
        tree_selection_style = f"""
            QTreeWidget::item:selected {{
                background-color: {colors.selection_background};
                color: {colors.selection_text};
            }}
            QTreeWidget::item:selected:!active {{
                background-color: {colors.selection_inactive};
                color: {colors.selection_text};
            }}
        """
        
        if hasattr(self.ui, 'tw_similar_files'):
            current_tree_style = self.ui.tw_similar_files.styleSheet()
            if "QTreeWidget::item:selected" in current_tree_style:
                import re
                pattern = r'QTreeWidget::item:selected[^}]*}[^}]*}'
                current_tree_style = re.sub(pattern, '', current_tree_style)
            
            self.ui.tw_similar_files.setStyleSheet(current_tree_style + tree_selection_style)
        
        # Update match details table selection styling
        if hasattr(self.ui, 'tw_match_details'):
            self.ui.tw_match_details.setStyleSheet(tree_selection_style.replace('QTreeWidget', 'QTableWidget'))
        
        # Update checkbox icons with theme colors
        self.update_checkbox_icons(theme)
        
        # Update editor fonts with theme font settings
        self._setup_monospace_fonts()
        
        # Force text editor selection colors using palette
        self._update_text_editor_palette(theme)

    def _update_text_editor_palette(self, theme):
        """Force text editor selection colors using direct stylesheet"""
        
        # Get all text editors in the UI
        text_editors = []
        if hasattr(self.ui, 'te_rule_content'):
            text_editors.append(self.ui.te_rule_content)
        if hasattr(self.ui, 'te_file_content'):
            text_editors.append(self.ui.te_file_content)
        
        # Create direct stylesheet for text editor selection
        selection_stylesheet = f"""
        QTextEdit, QPlainTextEdit {{
            selection-background-color: {theme.colors.editor_selection};
            selection-color: {theme.colors.editor_text};
        }}
        """
        
        for editor in text_editors:
            # Apply the direct selection stylesheet to each editor
            editor.setStyleSheet(selection_stylesheet)
            
            # Configure scrollbars to only show when needed
            from PySide6.QtCore import Qt
            editor.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            editor.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            
            # Refresh current line highlighting with new theme colors
            if hasattr(editor, 'cursorPositionChanged'):
                # Trigger current line highlight refresh
                editor.cursorPositionChanged.emit()
    
    def create_checkbox_icon(self, size=16, checked=False, theme=None):
        """Create a custom checkbox icon with proper checkmark"""
        if theme is None:
            theme = self.theme_manager.current_theme
        
        colors = theme.colors
        
        # Create pixmap
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        # Create painter
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw checkbox border and background
        if checked:
            # Checked: white background with colored border
            painter.fillRect(1, 1, size-2, size-2, Qt.GlobalColor.white)
            pen = QPen(Qt.GlobalColor.red, 2)  # Red border for checked
        else:
            # Unchecked: light background with gray border  
            painter.fillRect(1, 1, size-2, size-2, Qt.GlobalColor.white)
            pen = QPen(Qt.GlobalColor.gray, 1)  # Gray border for unchecked
        
        painter.setPen(pen)
        painter.drawRect(1, 1, size-3, size-3)
        
        if checked:
            # Draw checkmark
            pen = QPen(Qt.GlobalColor.red, 2)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            
            # Draw checkmark path
            # Start from left-middle, go to bottom-center, then to top-right
            checkmark_points = [
                (size * 0.25, size * 0.5),      # Left point
                (size * 0.45, size * 0.7),      # Bottom point  
                (size * 0.75, size * 0.3)       # Right point
            ]
            
            # Draw the checkmark lines
            painter.drawLine(int(checkmark_points[0][0]), int(checkmark_points[0][1]),
                           int(checkmark_points[1][0]), int(checkmark_points[1][1]))
            painter.drawLine(int(checkmark_points[1][0]), int(checkmark_points[1][1]),
                           int(checkmark_points[2][0]), int(checkmark_points[2][1]))
        
        painter.end()
        return QIcon(pixmap)

    def update_checkbox_icons(self, theme):
        """Update tree view checkbox icons with theme-appropriate colors"""
        # Create custom checkbox icons
        checked_icon = self.create_checkbox_icon(16, checked=True, theme=theme)
        unchecked_icon = self.create_checkbox_icon(16, checked=False, theme=theme)
        
        # Apply to the file system tree view
        if hasattr(self, 'fs_view'):
            # Note: Qt doesn't have a direct way to set checkbox icons via stylesheet
            # We would need to implement a custom delegate or use a different approach
            # TODO: Implement custom delegate for checkbox styling
            return

    def on_browse_yara(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open YARA rule", self.last_dir, "YARA files (*.yar *.yara);;All files (*)"
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            QMessageBox.critical(self, "Open failed", f"Could not read file:\n{e}")
            return
        # Use helper to load text into editor with size check to avoid UI hangs
        self._load_text_to_editor(text, source_path=path)

    def on_yara_text_changed(self):
        """Invalidate compiled rules when YARA text is modified"""
        # Clear AST cache in syntax highlighter for accurate highlighting
        if hasattr(self, 'highlighter') and self.highlighter:
            self.highlighter.clear_ast_cache()
        
        # If rules were compiled, invalidate them since text changed
        if self.compiled_rules is not None:
            self.compiled_rules = None
            self.ui.tb_compilation_output.setHtml(
                '<span style="color: orange;">ℹ️ Rules modified - please recompile before scanning</span>'
            )
            self.statusBar().showMessage("⚠ Rules modified - recompile required", 3000)

    def _load_text_to_editor(self, text: str, source_path: str | None = None):
        """Load text into the editor after checking file size.

        If the file is too large for AST parsing, show a warning once per session
        and disable AST highlighting before inserting the text to avoid hangs.
        """
        try:
            size = len(text)
            # Determine limit from highlighter if available
            limit = None
            if hasattr(self, 'highlighter') and self.highlighter:
                limit = getattr(self.highlighter, '_max_file_size_for_ast', None)

            if limit is None:
                limit = 100 * 1024  # default 100KB

            # If too large, inform user (once per session) and disable AST highlighting
            if size > limit:
                if not getattr(self, '_size_warning_shown', False):
                    self._size_warning_shown = True
                    try:
                        QMessageBox.warning(
                            self,
                            "File Too Large for Syntax Highlighting",
                            f"File size ({size // 1024}KB) exceeds the highlighting limit ({limit // 1024}KB).\n\n"
                            "Syntax highlighting will be disabled for this file to maintain performance.\n"
                            "The file will load normally without highlighting."
                        )
                    except Exception:
                        # If QMessageBox cannot be shown, fall back to console
                        print(f"File too large ({size} chars) for AST highlighting; loading without highlighting")

                # Disable AST highlighting before setting the text to avoid parsing on main thread
                if hasattr(self, 'highlighter') and self.highlighter:
                    self.highlighter.set_ast_enabled(False)
            else:
                # Ensure AST highlighting is enabled for small files
                if hasattr(self, 'highlighter') and self.highlighter:
                    self.highlighter.set_ast_enabled(True)

            # Finally set the editor text (AST highlighting already disabled for large files)
            self.ui.te_yara_editor.setPlainText(text)

            if source_path:
                self.last_dir = str(Path(source_path).parent)
                self.statusBar().showMessage(f"Loaded YARA: {source_path}", 4000)

        except Exception as e:
            QMessageBox.critical(self, "Load failed", f"Could not load YARA text:\n{e}")
    
    def on_save_rule(self):
        """Save the YARA rule from the editor to a file"""
        # Get the current text
        text = self.ui.te_yara_editor.toPlainText()

        if not text.strip():
            QMessageBox.warning(self, "Empty Rule", "No YARA rule to save.")
            return

        # Open save dialog
        path, _ = QFileDialog.getSaveFileName(
            self, "Save YARA rule", self.last_dir, "YARA files (*.yar *.yara);;All files (*)"
        )

        if not path:
            return

        # Ensure file has an extension
        if not path.endswith(('.yar', '.yara')):
            path += '.yar'

        try:
            Path(path).write_text(text, encoding="utf-8")
            self.last_dir = str(Path(path).parent)
            self.statusBar().showMessage(f"YARA rule saved: {path}", 4000)
        except Exception as e:
            QMessageBox.critical(self, "Save failed", f"Could not save file:\n{e}")

    def on_reset(self):
        """Reset everything to a completely fresh start"""
        reply = QMessageBox.question(
            self, "Reset All", 
            "This will clear ALL data:\n• YARA editor\n• Compilation output\n• Scan results\n• Directory selection\n• All tables and lists\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Clear YARA editor and compilation
            self.ui.te_yara_editor.clear()
            self.compiled_rules = None
            
            # Clear all scan data
            self.scan_hits = []
            self.scan_misses = []
            self.misses_loaded = False
            self.scan_root = None
            
            # Clear all table models
            self.hits_model.clear()
            self.hits_model.setHorizontalHeaderLabels(['File', 'Path'])
            
            self.misses_model.clear()
            self.misses_model.setHorizontalHeaderLabels(['File', 'Path'])
            
            self.rule_details_model.clear()
            self.rule_details_model.setHorizontalHeaderLabels(['Property', 'Value'])
            
            # Clear similar files tree
            self.ui.tw_similar_files.clear()
            self.ui.tw_similar_files.setHeaderLabels(['File/Rule', 'Info'])
            
            # Clear similar tags tree (if it exists)
            if hasattr(self.ui, 'tw_similar_tags'):
                self.ui.tw_similar_tags.clear()
                self.ui.tw_similar_tags.setHeaderLabels(['Tag/File', 'Details'])
            
            # Clear YARA match details table
            if hasattr(self, 'tw_yara_match_details'):
                self.tw_yara_match_details.setRowCount(0)
            
            # Clear exclusion list
            self.ui.listWidget.clear()
            
            # Reset directory tree
            self.fs_view.setRootIndex(QModelIndex())  # Empty tree
            self.fs_model.exclusions.clear()  # Clear exclusions
            
            # Clear and reset compilation output with helpful message
            self.ui.tb_compilation_output.clear()  # Explicitly clear first
            self.ui.tb_compilation_output.setHtml(
                '<span style="color: gray;"><b>Complete reset performed</b></span><br><br>'
                '<b>Steps to get started:</b><br>'
                '1. Load or write YARA rules in the editor above<br>'
                '2. Click <b>"Compile"</b> to validate your rules<br>'
                '3. Click <b>"Select Scan Dir"</b> to choose what to scan<br>'
                '4. Click <b>"SCAN"</b> to start the scan<br>'
            )
            
            # Reset AST highlighting settings
            if hasattr(self, 'highlighter') and self.highlighter:
                self.highlighter.set_ast_enabled(True)  # Re-enable AST highlighting
                self.highlighter.clear_ast_cache()      # Clear any cached data
            
            # Reset size warning flag so it can show again for large files
            self._size_warning_shown = False
            
            # Switch back to the directory selection tab
            self.ui.tabWidget.setCurrentIndex(0)  # Switch to Scan Dir tab
            
            self.statusBar().showMessage("Complete reset - ready for fresh start", 5000)

    def on_format_yara(self) -> None:
        """Format the YARA rule in the editor using yaraast for proper AST-based formatting."""
        text = self.ui.te_yara_editor.toPlainText()
        
        if not text.strip():
            QMessageBox.information(self, "No Content", "No YARA rule to format.")
            return
        
        # Only format if yaraast is available and can successfully parse the rule
        if not YARAAST_AVAILABLE:
            QMessageBox.warning(self, "AST Parser Required", 
                               "yaraast library is required for formatting. Please install it first.")
            return
        
        try:
            # Try AST parsing first - if it fails, do NOT format at all
            formatted_text = self.format_yara_with_ast(text)
            
            # Load formatted text via helper to enforce size checks (should be small)
            self._load_text_to_editor(formatted_text)
            
            # Show success message
            self.statusBar().showMessage("YARA rule formatted with AST parser", 3000)
                
        except Exception as e:
            # If AST parsing fails, do NOT format - show error instead
            QMessageBox.warning(self, "Cannot Format Rule", 
                               f"Unable to format YARA rule due to syntax errors:\n\n{str(e)}\n\n"
                               "Please fix the syntax errors first, then try formatting again.")
            self.statusBar().showMessage(f"Formatting failed: {str(e)[:50]}...", 5000)

    def format_yara_with_ast(self, text: str) -> str:
        """
        Format YARA rules using yaraast AST parser.
        
        Args:
            text: Raw YARA rule text to format
            
        Returns:
            Formatted YARA rule text
            
        Raises:
            Exception: If AST parsing fails
        """
        try:
            # Parse the YARA rule text using the correct API
            parser = Parser()
            ast = parser.parse(text)
            
            # Generate properly formatted output using CodeGenerator
            codegen = CodeGenerator()
            formatted = codegen.generate(ast)
            
            return formatted
            
        except Exception as e:
            raise Exception(f"yaraast parsing failed: {str(e)}")

    def validate_yara_syntax(self, text):
        """Validate YARA syntax using yaraast and provide detailed feedback"""
        if not YARAAST_AVAILABLE:
            return {"valid": None, "message": "yaraast not available for syntax validation"}
        
        try:
            # Parse using the correct API
            parser = Parser()
            ast = parser.parse(text)
            
            # Collect validation info
            rules_info = []
            total_strings = 0
            total_tags = 0
            
            for rule in ast.rules:
                rule_info = {
                    'name': rule.name,
                    'tags': list(rule.tags) if hasattr(rule, 'tags') and rule.tags else [],
                    'strings': len(rule.strings) if hasattr(rule, 'strings') and rule.strings else 0,
                    'meta': len(rule.meta) if hasattr(rule, 'meta') and rule.meta else 0,
                    'has_condition': hasattr(rule, 'condition') and rule.condition is not None
                }
                rules_info.append(rule_info)
                total_strings += rule_info['strings']
                total_tags += len(rule_info['tags'])
            
            return {
                "valid": True,
                "rules_count": len(rules_info),
                "total_strings": total_strings,
                "total_tags": total_tags,
                "rules_info": rules_info,
                "message": f"✓ Syntax valid: {len(rules_info)} rules, {total_strings} strings, {total_tags} tags"
            }
            
        except Exception as e:
            return {
                "valid": False,
                "message": f"✗ Syntax error: {str(e)}",
                "error": str(e)
            }

    def get_yara_rule_info(self, text):
        """Get detailed information about YARA rules using AST analysis"""
        if not YARAAST_AVAILABLE:
            return "yaraast not available - install with: pip install yaraast[all]"
        
        try:
            validation = self.validate_yara_syntax(text)
            if not validation["valid"]:
                return f"Syntax Error: {validation['message']}"
            
            info_lines = [
                f"📊 YARA Rule Analysis:",
                f"  Rules: {validation['rules_count']}",
                f"  Total Strings: {validation['total_strings']}",
                f"  Total Tags: {validation['total_tags']}",
                ""
            ]
            
            for i, rule in enumerate(validation['rules_info'], 1):
                info_lines.append(f"Rule {i}: {rule['name']}")
                info_lines.append(f"  📄 Strings: {rule['strings']}")
                info_lines.append(f"  🏷️  Tags: {', '.join(rule['tags']) if rule['tags'] else 'None'}")
                info_lines.append(f"  📊 Meta: {rule['meta']} entries")
                info_lines.append(f"  ✅ Condition: {'Yes' if rule['has_condition'] else 'No'}")
                info_lines.append("")
            
            return '\n'.join(info_lines)
            
        except Exception as e:
            return f"Analysis failed: {str(e)}"

    def on_scan(self) -> None:
        """Scan selected files with compiled YARA rules and populate results tabs."""
        if not self._validate_scan_prerequisites():
            return
            
        rule_text = self.ui.te_yara_editor.toPlainText()
        
        # Compile rules first
        compiled_rules = self._compile_yara_rules(rule_text)
        if not compiled_rules:
            return
        
        # Prepare for scanning
        self._prepare_scan_ui()
        
        # Collect files to scan
        files_to_scan = list(self.iter_selected_files())
        if not files_to_scan:
            self.ui.tb_compilation_output.append("⚠ No files to scan (all excluded or empty directory).")
            self.statusBar().showMessage("No files to scan", 3000)
            return
        
        # Perform the actual scanning
        scan_stats = self._perform_file_scanning(compiled_rules, files_to_scan)
        
        # Finalize results
        self._finalize_scan_results(scan_stats)

    def _validate_scan_prerequisites(self) -> bool:
        """Validate that all prerequisites for scanning are met."""
        if not YARA_X_AVAILABLE:
            self.ui.tb_compilation_output.setHtml(
                '<span style="color: red; font-weight: bold;">✗ YARA-X not installed!</span><br><br>'
                'Please install it with: <code>pip install yara-x</code>'
            )
            self.statusBar().showMessage("YARA-X not installed", 4000)
            return False

        rule_text = self.ui.te_yara_editor.toPlainText()
        if not rule_text.strip():
            QMessageBox.warning(self, "No YARA Rule", "Please load or write a YARA rule first.")
            return False

        if self.scan_root is None:
            QMessageBox.warning(self, "No Scan Directory", "Please select a directory to scan first.")
            return False
            
        return True
    
    def _compile_yara_rules(self, rule_text: str):
        """Compile YARA rules and return compiled rules object or None on failure."""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        try:
            self.ui.tb_compilation_output.setHtml(
                f'<span style="color: blue;">[{timestamp}] Compiling YARA rules...</span>'
            )
            QApplication.processEvents()
            
            import yara_x
            rules = yara_x.compile(rule_text)
            
            self.ui.tb_compilation_output.append(
                f'\n<span style="color: green; font-weight: bold;">✓ Compilation successful!</span>\n'
            )
            QApplication.processEvents()
            return rules
            
        except Exception as e:
            self._handle_error(e, "YARA compilation")
            # Show error message box for immediate user notification
            self._show_compilation_error_dialog(str(e))
            return None
    
    def _prepare_scan_ui(self) -> None:
        """Prepare the UI for scanning by switching tabs and clearing results."""
        # Switch to Scan Result tab and focus on Hits
        self.ui.tabWidget.setCurrentWidget(self.ui.tab_scan_results)
        self.ui.tabWidget_2.setCurrentIndex(0)  # Focus on Hits tab
        
        # Clear previous results
        self.scan_hits.clear()
        self.scan_misses.clear()
        self.misses_loaded = False
        
        self.hits_model.clear()
        self.hits_model.setHorizontalHeaderLabels(['Filename', 'Full Path'])
        
        self.misses_model.clear()
        self.misses_model.setHorizontalHeaderLabels(['Filename', 'Full Path'])
        
        self.rule_details_model.clear()
        self.rule_details_model.setHorizontalHeaderLabels(['Property', 'Value'])
    
    def _perform_file_scanning(self, rules, files_to_scan: List[Path]) -> Dict[str, int]:
        """Perform the actual file scanning and return statistics."""
        self.ui.tb_compilation_output.append(f"Scanning {len(files_to_scan)} files...\n")
        self.statusBar().showMessage(f"Scanning {len(files_to_scan)} files...", 0)
        QApplication.processEvents()

        # Initialize counters
        stats = {'scanned': 0, 'matches': 0, 'errors': 0}

        for file_path in files_to_scan:
            stats['scanned'] += 1

            # Update progress every 10 files
            if stats['scanned'] % 10 == 0:
                self.statusBar().showMessage(
                    f"Scanning... {stats['scanned']}/{len(files_to_scan)} files", 0
                )
                QApplication.processEvents()

            try:
                if self._scan_single_file(rules, file_path):
                    stats['matches'] += 1
            except PermissionError:
                stats['errors'] += 1
            except Exception as e:
                stats['errors'] += 1
                self.ui.tb_compilation_output.append(f"\n✗ Error scanning {file_path}: {e}")
                QApplication.processEvents()

        return stats
    
    def _scan_single_file(self, rules, file_path: Path) -> bool:
        """
        Scan a single file and add results to appropriate collections.
        
        Returns:
            True if file had matches, False otherwise
        """
        # Read file and calculate SHA256
        data = file_path.read_bytes()
        sha256_hash = hashlib.sha256(data).hexdigest()
        
        # Scan with YARA
        results = rules.scan(data)

        filename = file_path.name
        filepath = str(file_path)

        if results.matching_rules:
            # Process matches
            matched_rules = self._extract_match_details(results.matching_rules)
            
            hit_data = {
                'filename': filename,
                'filepath': filepath,
                'sha256': sha256_hash,
                'matched_rules': matched_rules
            }
            self.scan_hits.append(hit_data)
            
            # Add to hits table
            self._add_hit_to_table(filename, filepath, matched_rules)
            return True
        else:
            # Add to misses (lazy loading)
            miss_data = {
                'filename': filename,
                'filepath': filepath,
                'sha256': sha256_hash
            }
            self.scan_misses.append(miss_data)
            return False
    
    def _extract_match_details(self, matching_rules) -> List[Dict]:
        """Extract detailed information from matching rules."""
        matched_rules = []
        
        for rule in matching_rules:
            rule_info = {
                'identifier': rule.identifier,
                'namespace': rule.namespace,
                'tags': list(rule.tags) if hasattr(rule, 'tags') else [],
                'metadata': dict(rule.metadata) if hasattr(rule, 'metadata') else {},
                'patterns': []
            }
            
            # Extract pattern matches
            for pattern in rule.patterns:
                if pattern.matches:
                    pattern_info = {
                        'identifier': pattern.identifier,
                        'matches': [
                            {
                                'offset': match.offset,
                                'length': match.length
                            } for match in pattern.matches
                        ]
                    }
                    rule_info['patterns'].append(pattern_info)
            
            matched_rules.append(rule_info)
        
        return matched_rules
    
    def _add_hit_to_table(self, filename: str, filepath: str, matched_rules: List[Dict]) -> None:
        """Add a hit to the hits table with appropriate styling."""
        rules_count = len(matched_rules)
        
        # Choose display based on severity
        if rules_count == 1:
            filename_display = f"⚠ {filename}"
        elif rules_count <= 3:
            filename_display = f"🔴 {filename} ({rules_count})"
        else:
            filename_display = f"🚨 {filename} ({rules_count})"
        
        filename_item = QStandardItem(filename_display)
        filename_item.setToolTip(
            f"File: {filename}\nRules matched: {', '.join([r['identifier'] for r in matched_rules])}"
        )
        
        filepath_item = QStandardItem(filepath)
        filepath_item.setToolTip(filepath)
        
        self.hits_model.appendRow([filename_item, filepath_item])
    
    def _finalize_scan_results(self, stats: Dict[str, int]) -> None:
        """Finalize scan results and update UI."""
        # Format table
        self._force_thin_rows(self.ui.tv_file_hits)
        self.ui.tv_file_hits.resizeColumnToContents(0)
        
        # Switch to results tab
        self.ui.tabWidget.setCurrentIndex(1)
        self.ui.tabWidget_2.setCurrentIndex(0)
        
        # Populate additional views
        self.populate_similar_files()
        # Similar tags will be populated when user selects a file
        self._initialize_similar_tags_widget()
        self.populate_yara_match_details()

        # Show summary
        self._display_scan_summary(stats)

    def _display_scan_summary(self, stats: Dict[str, int]) -> None:
        """Display scan completion summary."""
        self.ui.tb_compilation_output.append("\n=== Scan Complete ===")
        self.ui.tb_compilation_output.append(f"Files scanned: {stats['scanned']}")
        self.ui.tb_compilation_output.append(f"Matches found: {stats['matches']}")
        self.ui.tb_compilation_output.append(f"Files without matches: {len(self.scan_misses)}")
        
        if stats['errors'] > 0:
            self.ui.tb_compilation_output.append(f"Errors: {stats['errors']}")

        if stats['matches'] > 0:
            self.ui.tb_compilation_output.append(f"\n✓ Results populated in Scan Results tab")
        else:
            self.ui.tb_compilation_output.append(f"\n✓ No threats detected - all files clean")

        self.statusBar().showMessage(
            f"Scan complete: {stats['scanned']} files, {stats['matches']} matches",
            10000
        )

    def on_select_scan_dir(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select folder to scan", self.last_dir,
            options=QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks,
        )
        if not path:
            return

        self.scan_root = Path(path).resolve()
        self.last_dir = str(self.scan_root)

        root_idx = self.fs_model.setRootPath(str(self.scan_root))
        self.fs_view.setRootIndex(root_idx)
        self.fs_view.expand(root_idx)
        self.statusBar().showMessage(f"Selected root: {path} (all files selected by default)", 4000)
        self.update_exclusion_list()

        # Focus on the file tree tab
        self.ui.tabWidget.setCurrentWidget(self.ui.tab_scan_dir)  # Switch to Tab 1

    def on_tree_expanded(self, index: QModelIndex):
        """When user expands a node, update the checkboxes of its immediate children"""
        row_count = self.fs_model.rowCount(index)
        for row in range(row_count):
            child_index = self.fs_model.index(row, 0, index)
            if child_index.isValid():
                # Trigger checkbox update
                self.fs_model.dataChanged.emit(child_index, child_index, [Qt.CheckStateRole])

    def update_exclusion_list(self):
        """Update list widget to show EXCLUDED items"""
        self.ui.listWidget.clear()

        if self.scan_root is None:
            return

        exclusions = self.fs_model.get_exclusion_list()

        if not exclusions:
            # No exclusions - everything will be scanned
            info_item = QListWidgetItem("✓ All files will be scanned (no exclusions)")
            info_item.setData(Qt.UserRole, None)
            self.ui.listWidget.addItem(info_item)

            help_item = QListWidgetItem("   💡 Uncheck items in the tree to exclude them from scanning")
            help_item.setData(Qt.UserRole, None)
            self.ui.listWidget.addItem(help_item)

            help_item2 = QListWidgetItem("   💡 Unchecked folders = entire folder tree is skipped")
            help_item2.setData(Qt.UserRole, None)
            self.ui.listWidget.addItem(help_item2)

            self.statusBar().showMessage("All files selected (no exclusions)", 3000)
        else:
            # Show excluded items
            header_item = QListWidgetItem(f"🚫 Excluded from scan ({len(exclusions)} items):")
            header_item.setData(Qt.UserRole, None)
            self.ui.listWidget.addItem(header_item)

            help_item = QListWidgetItem("   ℹ️ These items and their children will be skipped")
            help_item.setData(Qt.UserRole, None)
            self.ui.listWidget.addItem(help_item)

            self.ui.listWidget.addItem(QListWidgetItem(""))  # Blank line

            for path in exclusions:
                p = Path(path)
                if p.is_dir():
                    item = QListWidgetItem(f"   📁 {path.replace(os.sep, '/')}")
                else:
                    item = QListWidgetItem(f"   📄 {path.replace(os.sep, '/')}")
                item.setData(Qt.UserRole, path)
                self.ui.listWidget.addItem(item)

            self.statusBar().showMessage(f"{len(exclusions)} item(s) excluded from scanning", 3000)

    def get_exclusion_list(self) -> list[Path]:
        """Get list of excluded paths (for saving/loading exclusions)"""
        return [Path(p) for p in self.fs_model.get_exclusion_list()]

    def iter_selected_files(self):
        """
        Iterate over files that should be scanned.
        Yields Path objects, skipping excluded files/directories.
        IMPORTANT: If a directory is excluded, we don't traverse into it at all.
        """
        if self.scan_root is None:
            return

        # Manual directory walk to avoid traversing into excluded directories
        for root, dirs, files in os.walk(self.scan_root):
            root_path = Path(root)

            # Check if current directory is excluded
            if self.fs_model.is_excluded(root_path):
                # Skip this entire directory tree
                dirs.clear()  # Don't descend into subdirectories
                continue

            # Filter out excluded subdirectories from dirs (modifies in-place)
            dirs_to_remove = []
            for dir_name in dirs:
                dir_path = root_path / dir_name
                if self.fs_model.is_excluded(dir_path):
                    dirs_to_remove.append(dir_name)

            for dir_name in dirs_to_remove:
                dirs.remove(dir_name)

            # Yield non-excluded files
            for file_name in files:
                file_path = root_path / file_name
                if not self.fs_model.is_excluded(file_path):
                    yield file_path

    def on_results_tab_changed(self, index):
        """Handle tab changes in scan results - lazy load misses when needed"""
        if index == 1 and not self.misses_loaded:  # Misses tab (index 1)
            self.populate_misses_tab()

    def on_hit_selected(self, current, previous):
        """Handle selection of a hit file to show rule details and similar files"""
        if not current.isValid() or self._updating_selection:
            return
            
        # Get the filename from the selected row in the hits table
        row = current.row()
        filename_item = self.hits_model.item(row, 0)  # First column has filename
        if not filename_item:
            return
        
        # Extract the actual filename (remove emoji prefixes like ⚠, 🔴, 🚨)
        filename_display = filename_item.text()
        # Remove emoji and count info to get clean filename
        import re
        filename = re.sub(r'^[⚠🔴🚨]\s*', '', filename_display)  # Remove emoji prefix
        filename = re.sub(r'\s*\(\d+\)$', '', filename)  # Remove count suffix like (3)
        filename = filename.strip()
        
        # Find the first hit data entry for this filename
        hit_data = None
        for hit in self.scan_hits:
            if hit.get('filename') == filename:
                hit_data = hit
                break
        
        if not hit_data:
            return
            
        self.populate_rule_details(hit_data)
        self.populate_similar_files_for_selection(hit_data)
        self.populate_similar_tags_for_selection(hit_data)  # Add similar tags for selected file
        self.populate_yara_match_details(hit_data)

    def populate_misses_tab(self):
        """Populate the misses tab with files that had no matches"""
        if self.misses_loaded:
            return
            
        self.misses_model.clear()
        self.misses_model.setHorizontalHeaderLabels(['File', 'Path'])
        
        for miss_data in self.scan_misses:
            # Clean file with checkmark
            filename_display = f"🤡 {miss_data['filename']}"
            filename_item = QStandardItem(filename_display)
            filename_item.setToolTip(f"File: {miss_data['filename']}\nStatus: Clean (no threats)")
            
            # Compact path display
            filepath = miss_data['filepath']
            if len(filepath) > 50:
                path_display = f"...{filepath[-47:]}"
            else:
                path_display = filepath
            filepath_item = QStandardItem(path_display)
            filepath_item.setToolTip(filepath)
            
            self.misses_model.appendRow([filename_item, filepath_item])
        
        # Configure table view with thin rows
        header = self.ui.tv_file_misses.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        # Force thin rows
        self._force_thin_rows(self.ui.tv_file_misses)
        
        self.misses_loaded = True

    def populate_rule_details(self, hit_data):
        """Populate comprehensive rule details when a hit is selected"""
        self.rule_details_model.clear()
        self.rule_details_model.setHorizontalHeaderLabels(['Property', 'Value'])
        
        # File information - use short property names
        filename = hit_data['filename']
        filepath = hit_data['filepath']
        
        self.add_detail_row('📄 File', filename)
        self.add_detail_row('📁 Path', filepath)
        self.add_detail_row('🔑 Hash', hit_data['sha256'])
        
        # Rule summary
        rules = hit_data['matched_rules']
        self.add_detail_row('🎯 Rules', str(len(rules)))
        
        # Detailed rule information - simplified without match details
        for i, rule_info in enumerate(rules):
            prefix = f"R{i+1}" if len(rules) > 1 else "Rule"
            
            # Rule header with separator
            self.add_detail_row('──────────', '────────────────────────────────────────────')
            self.add_detail_row(f"📋 {prefix}", rule_info['identifier'])
            
            # Basic rule properties
            if rule_info.get('namespace', 'default') != 'default':
                self.add_detail_row('🗂️ NS', rule_info['namespace'])
            
            # Tags - show all tags prominently
            if 'tags' in rule_info and rule_info['tags']:
                tags_str = ', '.join(rule_info['tags'])
                self.add_detail_row('🏷️ Tags', tags_str)
            else:
                self.add_detail_row('🏷️ Tags', 'None')
            
            # Metadata section - show all metadata with short keys
            if 'metadata' in rule_info and rule_info['metadata']:
                meta_count = len(rule_info['metadata'])
                self.add_detail_row('📊 Meta', f"{meta_count} entries")
                for meta_key, meta_value in rule_info['metadata'].items():
                    # Format metadata nicely
                    if isinstance(meta_value, str):
                        display_value = meta_value
                    elif isinstance(meta_value, (int, float, bool)):
                        display_value = str(meta_value)
                    elif isinstance(meta_value, (list, tuple)):
                        display_value = ', '.join(str(v) for v in meta_value)
                    else:
                        display_value = str(meta_value)
                    
                    # Use shorter property name for metadata
                    short_key = meta_key[:12] + '...' if len(meta_key) > 15 else meta_key
                    self.add_detail_row(f"📌 {short_key}", display_value)
            
            # Simple pattern count without detailed match info
            patterns = rule_info.get('patterns', [])
            if patterns:
                pattern_count = len(patterns)
                self.add_detail_row('🎯 Patterns', f"{pattern_count} defined")
        
        # Ensure thin rows in rule details
        self._force_thin_rows(self.ui.tv_rule_details)
        
        # Configure columns - Property column fixed width, Value column gets remaining space
        header = self.ui.tv_rule_details.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)  # Fixed width for Property
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # Value gets all remaining space
        
        # Set Property column to reasonable fixed width (shorter names now)
        self.ui.tv_rule_details.setColumnWidth(0, 120)  # 120px for property names
        
        # Enable word wrap in the table to handle long values
        self.ui.tv_rule_details.setWordWrap(True)

    def add_detail_row(self, property_name, value):
        """Helper to add a row to rule details with proper value handling"""
        property_item = QStandardItem(property_name)
        
        # Convert value to string and handle long values
        value_str = str(value)
        value_item = QStandardItem(value_str)
        
        # Always show full text in tooltips
        property_item.setToolTip(property_name)
        value_item.setToolTip(value_str)
        
        # Allow text wrapping for long values
        value_item.setData(value_str, Qt.ItemDataRole.DisplayRole)
        
        self.rule_details_model.appendRow([property_item, value_item])
        self.ui.tv_rule_details.horizontalHeader().setStretchLastSection(True)

    def populate_similar_files(self):
        """Populate similar files tree based on rule matches"""
        from PySide6.QtWidgets import QTreeWidgetItem
        
        self.ui.tw_similar_files.clear()
        
        # Group hits by rule
        rule_files = {}
        for hit in self.scan_hits:
            for rule_info in hit['matched_rules']:
                rule_id = rule_info['identifier']
                if rule_id not in rule_files:
                    rule_files[rule_id] = []
                rule_files[rule_id].append({
                    'filename': hit['filename'],
                    'filepath': hit['filepath']
                })
        
        # Add to tree with hierarchical structure
        for rule_id, files in sorted(rule_files.items(), key=lambda x: len(x[1]), reverse=True):
            file_count = len(files)
            
            # Create rule parent item with visual indicator
            if file_count == 1:
                rule_display = f"🎯 {rule_id}"
            elif file_count <= 5:
                rule_display = f"🔥 {rule_id}"
            else:
                rule_display = f"🚨 {rule_id}"
            
            rule_item = QTreeWidgetItem([rule_display, f"{file_count} files"])
            rule_item.setToolTip(0, f"Rule: {rule_id}")
            rule_item.setToolTip(1, f"{file_count} files matched this rule")
            
            # Add file children
            for file_info in files:
                file_item = QTreeWidgetItem([f"📄 {file_info['filename']}", ""])
                file_item.setToolTip(0, f"File: {file_info['filename']}\nPath: {file_info['filepath']}")
                rule_item.addChild(file_item)
            
            self.ui.tw_similar_files.addTopLevelItem(rule_item)
            
            # Always expand by default
            rule_item.setExpanded(True)
        
        # Resize columns
        self.ui.tw_similar_files.resizeColumnToContents(0)
        self.ui.tw_similar_files.resizeColumnToContents(1)
        
        # Reset tab title to default
        if hasattr(self.ui, 'tabWidget_3'):
            tab_index = self.ui.tabWidget_3.indexOf(self.ui.tab_2)  # Similar Files tab
            if tab_index >= 0:
                self.ui.tabWidget_3.setTabText(tab_index, "Similar Files")

    def populate_similar_files_for_selection(self, selected_hit_data):
        """Populate similar files tree based on the selected hit's rules"""
        from PySide6.QtWidgets import QTreeWidgetItem
        
        self.ui.tw_similar_files.clear()
        
        # Get all rules from the selected file
        selected_rules = {rule['identifier'] for rule in selected_hit_data['matched_rules']}
        selected_filename = selected_hit_data['filename']
        
        # Group similar files by shared rules
        rule_groups = {}
        
        for hit in self.scan_hits:
            # Check if this file shares any rules with the selected file
            hit_rules = {rule['identifier'] for rule in hit['matched_rules']}
            shared_rules = selected_rules.intersection(hit_rules)
            
            if shared_rules:
                # Group by the shared rules combination
                shared_key = tuple(sorted(shared_rules))
                if shared_key not in rule_groups:
                    rule_groups[shared_key] = []
                
                rule_groups[shared_key].append({
                    'filename': hit['filename'],
                    'filepath': hit['filepath'],
                    'shared_count': len(shared_rules),
                    'is_selected': hit['filename'] == selected_filename
                })
        
        # Sort groups by number of shared rules (most similar first)
        sorted_groups = sorted(rule_groups.items(), key=lambda x: len(x[0]), reverse=True)
        
        # Add to tree grouped by shared rules
        for shared_rules_tuple, files in sorted_groups:
            shared_rules = list(shared_rules_tuple)
            shared_count = len(shared_rules)
            
            # Create rule group parent item
            if shared_count == len(selected_rules):
                group_display = f"🎯 Exact Match: {', '.join(shared_rules)}"
            elif shared_count > 1:
                group_display = f"🔥 Multiple Rules: {', '.join(shared_rules)}"
            else:
                group_display = f"⚠ Single Rule: {shared_rules[0]}"
            
            group_item = QTreeWidgetItem([group_display, f"{len(files)} files"])
            group_item.setToolTip(0, f"Shared rules: {', '.join(shared_rules)}")
            group_item.setToolTip(1, f"{len(files)} files share these rules with {selected_filename}")
            
            # Add file children
            for file_info in files:
                if file_info.get('is_selected', False):
                    # Mark the selected file with a star
                    file_display = f"📄 {file_info['filename']} ⭐"
                    tooltip_text = f"File: {file_info['filename']} (Selected)\nPath: {file_info['filepath']}"
                else:
                    file_display = f"📄 {file_info['filename']}"
                    tooltip_text = f"File: {file_info['filename']}\nPath: {file_info['filepath']}"
                
                file_item = QTreeWidgetItem([file_display, ""])
                file_item.setToolTip(0, tooltip_text)
                group_item.addChild(file_item)
            
            self.ui.tw_similar_files.addTopLevelItem(group_item)
            
            # Always expand by default
            group_item.setExpanded(True)
        
        # Resize columns
        self.ui.tw_similar_files.resizeColumnToContents(0)
        self.ui.tw_similar_files.resizeColumnToContents(1)
        
        # Update tab title to show it's based on selection
        if hasattr(self.ui, 'tabWidget_3'):
            tab_index = self.ui.tabWidget_3.indexOf(self.ui.tab_2)  # Similar Files tab
            if tab_index >= 0:
                total_files = sum(len(files) for _, files in sorted_groups)
                self.ui.tabWidget_3.setTabText(tab_index, f"Similar Files ({total_files})")

    def populate_similar_tags_for_selection(self, selected_hit_data):
        """Populate similar tags view based on the selected file's tags"""
        if not hasattr(self.ui, 'tw_similar_tags'):
            return  # Widget doesn't exist
            
        self.ui.tw_similar_tags.clear()
        
        if not self.scan_hits or not selected_hit_data:
            return
        
        selected_filename = selected_hit_data.get('filename', '')
        
        # Get all tags from the selected file's rules (from scan results only)
        selected_file_tags = set()
        for hit_data in self.scan_hits:
            if hit_data.get('filename') == selected_filename:
                # Extract tags from matched rules
                for rule_info in hit_data.get('matched_rules', []):
                    rule_name = rule_info.get('identifier', 'Unknown')
                    tags = rule_info.get('tags', [])
                    
                    for tag in tags:
                        if tag and tag.strip():
                            selected_file_tags.add(tag.strip())
        
        if not selected_file_tags:
            # No tags found for selected file
            no_tags_item = QTreeWidgetItem(["No tags found", ""])
            self.ui.tw_similar_tags.addTopLevelItem(no_tags_item)
            return
        
        # For each tag from the selected file, find other files with the same tag
        for tag in sorted(selected_file_tags):
            files_with_this_tag = []
            
            # Find all files (including the selected one) that have this tag
            for hit_data in self.scan_hits:
                filename = hit_data.get('filename', 'Unknown')
                filepath = hit_data.get('filepath', '')
                
                # Check each rule in this file for the tag
                for rule_info in hit_data.get('matched_rules', []):
                    rule_name = rule_info.get('identifier', 'Unknown')
                    tags = rule_info.get('tags', [])
                    
                    # Check if this rule has the current tag
                    if any(t.strip() == tag for t in tags if t and t.strip()):
                        # Avoid duplicates
                        if not any(f['filename'] == filename and f['rule_name'] == rule_name for f in files_with_this_tag):
                            files_with_this_tag.append({
                                'filename': filename,
                                'filepath': filepath,
                                'rule_name': rule_name,
                                'is_selected': filename == selected_filename
                            })
            
            # Only show tags that have at least one file match
            if files_with_this_tag:
                # Create tag item
                other_files_count = len([f for f in files_with_this_tag if not f['is_selected']])
                tag_display = f"🏷️ {tag}"
                if other_files_count > 0:
                    tag_info = f"Selected + {other_files_count} others"
                else:
                    tag_info = "Only in selected file"
                
                tag_item = QTreeWidgetItem([tag_display, tag_info])
                tag_item.setToolTip(0, f"Tag: {tag}")
                tag_item.setToolTip(1, f"Found in {len(files_with_this_tag)} files total")
                
                # Add file children
                for file_info in files_with_this_tag:
                    if file_info['is_selected']:
                        # Mark the selected file
                        file_display = f"📄 {file_info['filename']} ⭐"
                        file_info_text = f"Rule: {file_info['rule_name']} (Selected)"
                    else:
                        file_display = f"📄 {file_info['filename']}"
                        file_info_text = f"Rule: {file_info['rule_name']}"
                    
                    file_item = QTreeWidgetItem([file_display, file_info_text])
                    file_item.setToolTip(0, f"File: {file_info['filename']}\nPath: {file_info['filepath']}")
                    file_item.setToolTip(1, f"Rule: {file_info['rule_name']}")
                    tag_item.addChild(file_item)
                
                self.ui.tw_similar_tags.addTopLevelItem(tag_item)
                
                # Expand if there are few enough files to see clearly
                if len(files_with_this_tag) <= 5:
                    tag_item.setExpanded(True)
        
        # Resize columns
        self.ui.tw_similar_tags.resizeColumnToContents(0)
        self.ui.tw_similar_tags.resizeColumnToContents(1)
        
        # Update tab title
        if hasattr(self.ui, 'tabWidget_3'):
            for i in range(self.ui.tabWidget_3.count()):
                if hasattr(self.ui.tabWidget_3.widget(i), 'objectName'):
                    widget = self.ui.tabWidget_3.widget(i)
                    if hasattr(widget, 'findChild') and widget.findChild(type(self.ui.tw_similar_tags)):
                        total_tags = len(selected_file_tags)
                        break

    def _initialize_similar_tags_widget(self):
        """Initialize similar tags widget with instruction message"""
        if not hasattr(self.ui, 'tw_similar_tags'):
            return
            
        self.ui.tw_similar_tags.clear()
        instruction_item = QTreeWidgetItem(["Select a file to see similar tags", ""])
        instruction_item.setToolTip(0, "Click on a file in the hits table to see files with similar tags")
        self.ui.tw_similar_tags.addTopLevelItem(instruction_item)
        
        

    def populate_yara_match_details(self, hit_data=None):
        """Populate comprehensive YARA match details table widget for ALL files"""
        # Check if the match details table widget exists
        if not hasattr(self, 'tw_yara_match_details'):
            return
            
        from PySide6.QtWidgets import QTableWidgetItem
        from PySide6.QtCore import Qt
        
        # Clear existing data
        self.tw_yara_match_details.setRowCount(0)
        
        # If hit_data is provided, show only that file's matches (for compatibility)
        # Otherwise show ALL files with matches
        if hit_data:
            files_to_process = [hit_data]
        else:
            files_to_process = self.scan_hits
        
        # Collect all matches for the table from all files
        table_rows = []
        
        for file_data in files_to_process:
            filename = file_data['filename']
            filepath = file_data['filepath']
            matched_rules = file_data.get('matched_rules', [])
            
            for rule_idx, rule_match in enumerate(matched_rules):
                rule_name = rule_match.get('identifier', f'Rule_{rule_idx}')
                rule_tags = rule_match.get('tags', [])
                tags_str = ', '.join(rule_tags) if rule_tags else ''
                
                # Process each pattern in the rule
                patterns = rule_match.get('patterns', [])
                for pattern_idx, pattern in enumerate(patterns):
                    pattern_id = pattern.get('identifier', f'Pattern_{pattern_idx}')
                    matches = pattern.get('matches', [])
                    
                    # Add each match occurrence as a table row
                    for match_idx, match in enumerate(matches):
                        offset = match.get('offset', 0)
                        length = match.get('length', 0)
                        
                        # Get data preview for this match
                        data_preview = self._get_data_preview(filepath, offset, length)
                        preview_text = data_preview['text'] if data_preview else 'N/A'
                        hex_dump = data_preview['hex'] if data_preview else 'N/A'
                        
                        # Create table row data
                        row_data = [
                            filename,                           # File
                            rule_name,                         # Rule
                            pattern_id,                        # Pattern ID
                            f'0x{offset:08X}',                # Offset (hex)
                            preview_text,                      # Data Preview
                            hex_dump,                          # Hex Dump
                            tags_str                           # Tag
                        ]
                        
                        table_rows.append(row_data)
        
        # Populate the table
        self.tw_yara_match_details.setRowCount(len(table_rows))
        
        for row_idx, row_data in enumerate(table_rows):
            for col_idx, cell_data in enumerate(row_data):
                item = QTableWidgetItem(str(cell_data))
                # Make cells read-only but selectable
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                
                # Apply column-specific background colors
                self._apply_column_color(item, col_idx)
                
                self.tw_yara_match_details.setItem(row_idx, col_idx, item)
        
        # Make table compact with thin rows
        self._make_table_compact(self.tw_yara_match_details)
        
        # Resize columns to fit content initially
        self.tw_yara_match_details.resizeColumnsToContents()
        
        # Apply our configured column widths
        self.tw_yara_match_details.setColumnWidth(0, 200)  # File
        self.tw_yara_match_details.setColumnWidth(1, 150)  # Rule
        self.tw_yara_match_details.setColumnWidth(2, 100)  # Pattern ID
        self.tw_yara_match_details.setColumnWidth(3, 100)  # Offset
        self.tw_yara_match_details.setColumnWidth(4, 250)  # Data Preview
        self.tw_yara_match_details.setColumnWidth(5, 200)  # Hex Dump
        self.tw_yara_match_details.setColumnWidth(6, 100)  # Tag

    def on_match_detail_double_clicked(self, row, column):
        """Handle double-click of a match detail row to show more information"""
        if row < 0:
            return
        
        # Get data from the double-clicked row
        filename_item = self.tw_yara_match_details.item(row, 0)  # File
        rule_item = self.tw_yara_match_details.item(row, 1)      # Rule
        pattern_item = self.tw_yara_match_details.item(row, 2)   # Pattern ID
        offset_item = self.tw_yara_match_details.item(row, 3)    # Offset
        
        if not all([filename_item, rule_item, pattern_item, offset_item]):
            return
            
        filename = filename_item.text()
        rule_name = rule_item.text()
        pattern_id = pattern_item.text()
        offset_hex = offset_item.text()
        
        # Find the corresponding file data
        hit_data = None
        for scan_hit in self.scan_hits:
            if scan_hit['filename'] == filename:
                hit_data = scan_hit
                break
        
        if hit_data:
            # Show detailed info in a status message or tooltip
            filepath = hit_data['filepath']
            
            # Extract offset as integer
            try:
                offset = int(offset_hex, 16) if offset_hex.startswith('0x') else int(offset_hex)
                
                # Show expanded information in status bar
                msg = f"Selected: {filename} | Rule: {rule_name} | Pattern: {pattern_id} | Offset: {offset_hex} ({offset:,} dec) | Path: {filepath}"
                self.statusBar().showMessage(msg, 10000)
                
                # Update rule details to show info for this specific file
                self.populate_rule_details(hit_data)
                
                # Synchronize selection with hits list (without updating details to avoid recursion)
                self.select_file_in_hits_list(filename, update_details=False)
                
            except ValueError:
                self.statusBar().showMessage(f"Selected: {filename} | Rule: {rule_name} | Pattern: {pattern_id}", 5000)

    def on_similar_file_double_clicked(self, item, column):
        """Handle double-click of a similar file to synchronize with hits list"""
        if not item:
            return
        
        # Get the item text and check various formats
        item_text = item.text(0)
        
        filename = None
        
        # Check if this is a file item (try different formats)
        if item_text.startswith('📄 '):
            # Extract filename from the item text
            filename = item_text[2:]  # Remove the "📄 " prefix
        elif item_text.startswith('File: '):
            # Alternative format
            filename = item_text[6:]  # Remove the "File: " prefix
        elif not item.parent():
            # This might be a top-level item, check if it's a filename directly
            # Skip if it looks like a rule name or section header
            if not any(keyword in item_text.lower() for keyword in ['rule', 'condition', 'strings', 'meta']):
                filename = item_text
        
        if filename:
            # Find this file in the hits list and select it
            self.select_file_in_hits_list(filename)

    def on_similar_tag_double_clicked(self, item, column):
        """Handle double-click of a similar tag item to synchronize with hits list"""
        if not item:
            return
        
        # Get the item text and check various formats
        item_text = item.text(0)
        
        filename = None
        tag_name = None
        
        # Check if this is a file item under a tag
        if item_text.startswith('📄 '):
            # Extract filename from the item text
            filename = item_text[2:]  # Remove the "📄 " prefix
        elif item_text.startswith('🏷️ '):
            # This is a tag item - extract tag name
            tag_name = item_text[3:]  # Remove the "🏷️ " prefix
            
            # If it's a tag with children, select the first file with this tag
            if item.childCount() > 0:
                first_child = item.child(0)
                if first_child and first_child.text(0).startswith('📄 '):
                    filename = first_child.text(0)[2:]  # Remove "📄 " prefix
        
        if filename:
            # Find this file in the hits list and select it
            self.select_file_in_hits_list(filename)
            
            # If we have a tag, also highlight the tag in the editor
            if tag_name or (item.parent() and item.parent().text(0).startswith('🏷️ ')):
                parent_tag = tag_name if tag_name else item.parent().text(0)[3:]
                self.highlight_tag_in_editor(parent_tag)

    def highlight_tag_in_editor(self, tag_name):
        """Highlight the specified tag in the YARA editor"""
        if not tag_name:
            return
            
        # Get the editor content
        cursor = self.ui.te_yara_editor.textCursor()
        document = self.ui.te_yara_editor.document()
        
        # Search for the tag in the editor
        search_text = f'"{tag_name}"'
        
        # Find the tag in the document
        found_cursor = document.find(search_text)
        if not found_cursor.isNull():
            # Move cursor to the found position and select the tag
            found_cursor.select(QTextCursor.SelectionType.WordUnderCursor)
            self.ui.te_yara_editor.setTextCursor(found_cursor)
            
            # Scroll to make sure it's visible
            self.ui.te_yara_editor.ensureCursorVisible()
            
            # Show message
            self.statusBar().showMessage(f"Highlighted tag '{tag_name}' in YARA editor", 3000)
        else:
            self.statusBar().showMessage(f"Tag '{tag_name}' not found in current YARA rule", 3000)
    
    def select_file_in_hits_list(self, filename, update_details=True):
        """Select a specific file in the hits list and optionally update details"""
        if self._updating_selection:
            return  # Prevent recursive calls
            
        # Find the file in scan_hits and select it in the hits table
        for row, hit_data in enumerate(self.scan_hits):
            if hit_data['filename'] == filename:
                self._updating_selection = True
                try:
                    # Select the row in the hits table
                    self.ui.tv_file_hits.selectRow(row)
                    
                    if update_details:
                        # Update details for this file
                        self.populate_rule_details(hit_data)
                        self.populate_similar_files_for_selection(hit_data)
                        self.populate_yara_match_details(hit_data)
                        
                        # Update status bar to show the selection
                        filepath = hit_data['filepath']
                        rule_count = len(hit_data.get('matched_rules', []))
                        self.statusBar().showMessage(
                            f"Selected: {filename} | {rule_count} rule(s) matched | Path: {filepath}", 
                            8000
                        )
                finally:
                    self._updating_selection = False
                break

    def _get_data_preview(self, filepath, offset, length, preview_length=64):
        """Get a preview of data at the specified offset"""
        try:
            with open(filepath, 'rb') as f:
                f.seek(offset)
                # Read a bit more for context, but limit it
                read_length = min(preview_length, length + 16)
                data = f.read(read_length)
                
                if not data:
                    return None
                
                # Text preview (printable characters only)
                text_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[:preview_length])
                
                # Hex dump
                hex_dump = ' '.join(f'{b:02X}' for b in data[:preview_length])
                
                return {
                    'raw': data[:preview_length],
                    'text': text_preview,
                    'hex': hex_dump
                }
        except Exception:
            return None


if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = MainWindow()
    widget.show()
    sys.exit(app.exec())
