# This Python file uses the following encoding: utf-8

"""
YaraXGUI - A GUI application for YARA-X rule scanning and analysis.

Usage:
    pyside6-uic form.ui -o ui_form.py
"""

# Standard library imports
import fnmatch
import os
import re
import sys
from pathlib import Path
from typing import Dict, List

# Third-party imports
from PySide6.QtCore import QDir, QEvent, QModelIndex, QTimer, Qt
from PySide6.QtGui import (QIcon, QPainter, QPen, QPixmap, QStandardItem,
                           QTextCursor)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox,
                               QFileDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QListWidgetItem, QMenu, QMainWindow,
                               QMessageBox, QProgressBar, QPushButton,
                               QToolButton, QTreeView, QVBoxLayout, QWidget)

# Local imports
from checkable_fs_model import CheckableFsModel
from scan_results import ScanResultsManager
from scanner import YaraScanner, YARA_X_AVAILABLE, YARAAST_AVAILABLE
from scanner_worker import ScanWorker
from themes import theme_manager
from ui_form import Ui_MainWindow
from yara_editor import YaraTextEdit
from yara_highlighter import YaraHighlighter
from hex_editor import HexEditorWindow


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
        
        # Set custom window title and icon
        self.setWindowTitle("YaraXGUI - YARA Rule Scanner & Analyzer")
        self.setup_application_icon()

        # Scanner (pure logic, no UI)
        self.scanner = YaraScanner()

        # Scan results manager
        self.results = ScanResultsManager(self.ui, theme_manager, parent=self)

        # Replace the placeholder editor with YaraTextEdit (line numbers built in)
        new_editor = YaraTextEdit(self.ui.layoutWidget)
        self.ui.horizontalLayout.replaceWidget(self.ui.te_yara_editor, new_editor)
        self.ui.te_yara_editor.deleteLater()
        self.ui.te_yara_editor = new_editor

        # Syntax highlighter (must come after editor replacement)
        self.highlighter = YaraHighlighter(self.ui.te_yara_editor.document())

        # Set default template so the editor isn't blank on first launch
        self.ui.te_yara_editor.setPlainText(
            'rule example_rule {\n'
            '    meta:\n'
            '        author = ""\n'
            '        description = ""\n'
            '\n'
            '    strings:\n'
            '        $s1 = ""\n'
            '\n'
            '    condition:\n'
            '        any of them\n'
            '}\n'
        )

        # Connect cursor info to status bar
        self.ui.te_yara_editor.cursor_info_changed.connect(
            lambda msg: self.statusBar().showMessage(msg)
        )

        # Invalidate compiled rules when editor text changes
        self.ui.te_yara_editor.textChanged.connect(self.on_yara_text_changed)

        # File system model
        self.fs_model = CheckableFsModel(self)
        self.fs_model.setFilter(QDir.AllEntries | QDir.NoDotAndDotDot)
        self.fs_model.setReadOnly(True)
        # Don't set any root path - tree will be empty until user selects a directory

        # QTreeView
        self.fs_view = QTreeView(self.ui.tab_scan_dir)
        self.fs_view.setAlternatingRowColors(True)
        self.fs_view.setUniformRowHeights(True)
        self.fs_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.fs_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.fs_view.setSortingEnabled(True)
        self.fs_view.sortByColumn(0, Qt.AscendingOrder)
        
        # Don't connect model yet - tree should be empty until directory is selected
        # self.fs_view.setModel(self.fs_model) will be called in on_select_scan_dir

        header = self.fs_view.header()
        # Name column stretches to fill the rest; the fixed-width metadata
        # columns (size/type/date) start at reasonable defaults so Name
        # isn't squeezed to a sliver on startup. All three remain user-
        # resizable via Interactive mode.
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(False)
        header.resizeSection(1, 90)   # Size
        header.resizeSection(2, 100)  # Type
        header.resizeSection(3, 140)  # Date Modified
        self.fs_view.setColumnWidth(0, 420)  # Name — generous starting width

        # Build a container that pairs a filter bar with the file tree.
        # The filter bar lets the user quickly include/exclude files in
        # the current scan root by glob or regex pattern without having
        # to click through the tree.
        self.fs_container = QWidget(self.ui.tab_scan_dir)
        fs_layout = QVBoxLayout(self.fs_container)
        fs_layout.setContentsMargins(0, 0, 0, 0)
        fs_layout.setSpacing(3)
        fs_layout.addWidget(self._build_fs_filter_bar(self.fs_container))
        fs_layout.addWidget(self.fs_view, 1)

        # Replace treeWidget with the fs_container in the splitter
        self.ui.treeWidget.setVisible(False)  # Hide original immediately

        # QSplitter.replaceWidget requires an index, not the widget reference
        # The treeWidget should be the first widget (index 0) in splitter_3
        self.ui.splitter_3.replaceWidget(0, self.fs_container)
        self.ui.treeWidget.deleteLater()
        self.fs_container.setVisible(True)
        self.fs_view.setVisible(True)
        self.fs_container.show()
        self.fs_view.show()

        # Connect to expansion events to update children's checkboxes on-demand
        self.fs_view.expanded.connect(self.on_tree_expanded)

        # Context menu for file system tree: "Open in Hex Editor"
        self.fs_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.fs_view.customContextMenuRequested.connect(self._show_fs_context_menu)

        # Setup
        self.last_dir = str(Path.home())
        self.scan_root: Path | None = None
        self.compiled_rules = None  # Store compiled YARA rules
        
        # Flag to prevent recursive selection updates
        self._updating_selection = False
        
        # Scan results data
        self.scan_hits = []  # List of hit file data
        self.scan_misses = []  # List of miss file data

        # Background scan worker (None when idle)
        self._scan_worker: ScanWorker | None = None

        # Status-bar progress widgets (hidden until a scan starts)
        self._scan_progress = QProgressBar()
        self._scan_progress.setMaximumWidth(280)
        self._scan_progress.setMinimumWidth(180)
        self._scan_progress.setTextVisible(True)
        self._scan_progress.hide()
        self.statusBar().addPermanentWidget(self._scan_progress)

        self._scan_cancel_btn = QToolButton()
        self._scan_cancel_btn.setText("\u2716 Cancel")
        self._scan_cancel_btn.setToolTip("Cancel the running scan")
        self._scan_cancel_btn.hide()
        self._scan_cancel_btn.clicked.connect(self._on_scan_cancel_clicked)
        self.statusBar().addPermanentWidget(self._scan_cancel_btn)

        # Hex editor windows
        self._hex_editor_windows: list = []

        # Accept drops (directories -> scan root, files -> hex editor or
        # YARA editor for .yar/.yara). Child widgets that accept drops by
        # default (QPlainTextEdit, QTreeView) would otherwise swallow the
        # event, so we install an event filter to intercept URL drops
        # before they reach those widgets.
        self.setAcceptDrops(True)
        for w in (self.ui.te_yara_editor, self.fs_view, self.ui.tv_file_hits):
            w.setAcceptDrops(True)
            w.installEventFilter(self)
        
        # Setup scan results UI
        self.results.setup_scan_results_ui()

        # Connect hits selection to our handler (must be after model is set)
        self.ui.tv_file_hits.selectionModel().selectionChanged.connect(self.on_hits_selection_changed)

        # Context menu for hits table: "Open in Hex Editor"
        self.ui.tv_file_hits.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ui.tv_file_hits.customContextMenuRequested.connect(self._show_hits_context_menu)

        # Connect results manager signals
        self.results.file_selection_requested.connect(self._on_file_selection_requested)
        self.results.tag_highlight_requested.connect(self.highlight_tag_in_editor)
        self.results.status_message_requested.connect(lambda msg, timeout: self.statusBar().showMessage(msg, timeout))
        self.results.hex_editor_requested.connect(self.open_hex_editor)

        # Lazy load misses when tab changes
        self.ui.tabWidget_2.currentChanged.connect(self.on_results_tab_changed)
        
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
        
        # Reset interface to default state on application startup
        self.reset_interface_on_startup()

    def reset_interface_on_startup(self):
        """Reset the interface to default state when application starts"""
        # Reset all tab focus to default states (same as Reset button)
        # Main tabs: Focus on Scan Dir tab (index 0)
        self.ui.tabWidget.setCurrentIndex(0)  # Switch to Scan Dir tab
        
        # Scan Results sub-tabs: Focus on Hits tab (index 0) 
        if hasattr(self.ui, 'tabWidget_2'):
            self.ui.tabWidget_2.setCurrentIndex(0)  # Focus on Hits tab
        
        # Details sub-tabs: Focus on Rule Details tab (index 0)
        if hasattr(self.ui, 'tabWidget_3'):
            self.ui.tabWidget_3.setCurrentIndex(0)  # Focus on Rule Details tab
        
        # Match Details tabs: If there are match details sub-tabs, focus on default
        if hasattr(self.ui, 'tabWidget_4'):  # In case there's a 4th level of tabs
            self.ui.tabWidget_4.setCurrentIndex(0)
        
        # Initialize similar tags widget with instruction message
        self.results.initialize_similar_tags_widget()
        
        # Set status message
        self.statusBar().showMessage("Application ready - select directory and YARA rules to begin", 4000)

    def setup_application_icon(self):
        """Setup application icon from YaraXGUI.ico file"""
        from PySide6.QtGui import QIcon
        from pathlib import Path
        
        try:
            # Use the specific YaraXGUI.ico file
            icon_path = Path(__file__).parent / "assets" / "YaraXGUI.ico"
            
            if icon_path.exists():
                # Load the icon file
                icon = QIcon(str(icon_path))
                
                # Verify the icon was loaded properly
                if not icon.isNull():
                    self.setWindowIcon(icon)
                    print(f"✅ Application icon loaded successfully: {icon_path}")
                else:
                    print(f"❌ Failed to load icon - file may be corrupted: {icon_path}")
                    self._use_fallback_icon()
            else:
                print(f"❌ Icon file not found: {icon_path}")
                self._use_fallback_icon()
                
        except Exception as e:
            print(f"❌ Error setting up application icon: {e}")
            self._use_fallback_icon()

    def _use_fallback_icon(self):
        """Use a fallback icon when the main icon fails to load"""
        try:
            # Try to use a system icon as fallback
            icon = self.style().standardIcon(self.style().StandardPixmap.SP_FileDialogDetailedView)
            if not icon.isNull():
                self.setWindowIcon(icon)
                print("🔄 Using fallback system icon")
            else:
                print("⚠️  No icon available - running without window icon")
        except Exception as e:
            print(f"⚠️  Fallback icon also failed: {e}")

    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for the application"""
        from PySide6.QtGui import QShortcut, QKeySequence
        
        # Word wrap toggle: Ctrl+W
        self.wrap_shortcut = QShortcut(QKeySequence("Ctrl+W"), self)
        self.wrap_shortcut.activated.connect(self.toggle_word_wrap)
        
        # Save rule: Ctrl+S
        self.save_shortcut = QShortcut(QKeySequence("Ctrl+S"), self)
        self.save_shortcut.activated.connect(self.on_save_rule)

        # Hex editor: Ctrl+H
        self.hex_shortcut = QShortcut(QKeySequence("Ctrl+H"), self)
        self.hex_shortcut.activated.connect(lambda: self.open_hex_editor())

        # Track document modification for save prompts
        self._document_modified = False
        self._last_saved_text = self.ui.te_yara_editor.toPlainText()
        self.ui.te_yara_editor.textChanged.connect(self._on_editor_text_changed)

    def _on_editor_text_changed(self):
        """Track when document is modified"""
        current_text = self.ui.te_yara_editor.toPlainText()
        self._document_modified = current_text != self._last_saved_text

    def _has_unsaved_changes(self) -> bool:
        """Check if there are unsaved changes in the YARA editor"""
        current_text = self.ui.te_yara_editor.toPlainText().strip()
        if not current_text:
            return False  # Empty document doesn't need saving
        return self._document_modified
    
    def closeEvent(self, event):
        """Handle window close event - prompt for unsaved changes"""
        if self._has_unsaved_changes():
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "You have unsaved changes in the YARA editor.\nDo you want to save before closing?",
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Save
            )

            if reply == QMessageBox.StandardButton.Save:
                self.on_save_rule()
            elif reply == QMessageBox.StandardButton.Cancel:
                event.ignore()
                return

        # Stop any in-flight scan worker before the window goes away
        if self._scan_worker is not None and self._scan_worker.isRunning():
            self._scan_worker.cancel()
            # Give the worker up to 3 s to finish its current file gracefully
            if not self._scan_worker.wait(3000):
                self._scan_worker.terminate()
                self._scan_worker.wait(1000)

        event.accept()

    def toggle_word_wrap(self):
        """Toggle word wrap in the YARA editor."""
        enabled = self.ui.te_yara_editor.toggle_word_wrap()
        self.statusBar().showMessage(
            "Word wrap enabled" if enabled else "Word wrap disabled", 2000
        )

    def refresh_word_wrap_display(self):
        """Force refresh of word wrap display and line numbers."""
        self.ui.te_yara_editor.refresh_word_wrap_display()

    def resizeEvent(self, event):
        """Handle main window resize to improve word wrap responsiveness."""
        super().resizeEvent(event)
        if self.ui.te_yara_editor.word_wrap_enabled:
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
        
        # Rule Info action (if yara-x or yaraast is available)
        if YARA_X_AVAILABLE or YARAAST_AVAILABLE:
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
            rule_info = self.scanner.get_rule_info(text)
            
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

    # Utility Methods
    def _handle_error(self, error: Exception, context: str = "Operation") -> None:
        """
        Centralized error handling with consistent logging and user feedback.
        
        Args:
            error: The exception that occurred
            context: Description of the operation that failed
        """
        error_msg = str(error)
        
        # Format compilation error with better HTML formatting
        formatted_error = self._format_compilation_error(error_msg, context)
        
        # Log to compilation output for user visibility
        self.ui.tb_compilation_output.append(formatted_error)
        
        # Show simplified message in status bar
        status_msg = f"{context} failed: {error_msg[:80]}{'...' if len(error_msg) > 80 else ''}"
        self.statusBar().showMessage(status_msg, 5000)

    def _safe_get_item_info(self, item):
        """
        Safely extract information from a tree widget item to avoid RuntimeError.
        
        Args:
            item: QTreeWidgetItem to extract info from
            
        Returns:
            dict: Dictionary with item information or None if item is invalid
        """
        if not item:
            return None
            
        try:
            return {
                'text': item.text(0),
                'parent': item.parent(),
                'parent_text': item.parent().text(0) if item.parent() else None,
                'child_count': item.childCount(),
                'data': item.data(0, 32)  # Qt.UserRole
            }
        except RuntimeError:
            # Item was deleted
            return None

    def _format_compilation_error(self, error_msg: str, context: str) -> str:
        """
        Format compilation errors with nice HTML styling and better readability.
        
        Args:
            error_msg: The raw error message
            context: The context where the error occurred
            
        Returns:
            HTML-formatted error message
        """
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Get theme-aware colors
        theme_colors = self._get_theme_colors_for_output()
        
        # Parse common YARA error patterns for better formatting
        if "syntax error" in error_msg.lower():
            error_type = "Syntax Error"
            icon = "📝"
            color = "#d32f2f"  # Red
        elif "undefined" in error_msg.lower():
            error_type = "Undefined Reference"
            icon = "❓"
            color = "#f57c00"  # Orange
        elif "duplicate" in error_msg.lower():
            error_type = "Duplicate Definition"
            icon = "🔄"
            color = "#f57c00"  # Orange
        elif "compilation" in context.lower():
            error_type = "Compilation Error"
            icon = "❌"
            color = "#d32f2f"  # Red
        else:
            error_type = "Error"
            icon = "⚠️"
            color = "#d32f2f"  # Red
        
        # Extract line number if present
        line_info = ""
        import re
        line_match = re.search(r'line (\d+)', error_msg, re.IGNORECASE)
        if line_match:
            line_num = line_match.group(1)
            line_info = f'<span style="color: {theme_colors["secondary_text"]}; font-size: 12px;"> (Line {line_num})</span>'
        
        # Clean up the error message
        clean_error = error_msg.strip()
        if clean_error.startswith('line ') and ':' in clean_error:
            # Remove redundant line info from beginning
            clean_error = clean_error.split(':', 1)[1].strip()
        
        # Format the complete error with nice styling
        formatted_error = f'''
        <div style="border-left: 4px solid {color}; padding: 8px 12px; margin: 4px 0; background-color: {theme_colors["error_bg"]};">
            <div style="color: {color}; font-weight: bold; margin-bottom: 4px;">
                {icon} {error_type} <span style="color: {theme_colors["secondary_text"]}; font-size: 11px;">[{timestamp}]</span>{line_info}
            </div>
            <div style="color: {theme_colors["main_text"]}; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; line-height: 1.4;">
                {self._escape_html(clean_error)}
            </div>
        </div>
        '''
        
        return formatted_error

    def _get_theme_colors_for_output(self):
        """Get theme-appropriate colors for compilation output formatting"""
        # Default colors (for light theme)
        colors = {
            "main_text": "#333333",
            "secondary_text": "#666666", 
            "error_bg": "rgba(211, 47, 47, 0.1)"
        }
        
        # Check if we have a theme manager and current theme
        if hasattr(self, 'theme_manager') and self.theme_manager.current_theme:
            theme = self.theme_manager.current_theme
            if hasattr(theme, 'colors'):
                # Use theme colors for better dark mode support
                colors["main_text"] = theme.colors.editor_text
                colors["secondary_text"] = theme.colors.editor_text + "AA"  # Add some transparency
                
                # Adjust error background based on theme
                if "dark" in theme.name.lower():
                    colors["error_bg"] = "rgba(211, 47, 47, 0.2)"  # Slightly more visible in dark theme
                else:
                    colors["error_bg"] = "rgba(211, 47, 47, 0.1)"
        
        return colors

    def _escape_html(self, text: str) -> str:
        """Escape HTML characters in text for safe display"""
        import html
        return html.escape(text)
    
    def _show_compilation_error_dialog(self, error_msg: str) -> None:
        """
        Show compilation error dialog for immediate user notification.
        
        Args:
            error_msg: The compilation error message to display
        """
        from PySide6.QtWidgets import QMessageBox
        import re
        
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle("⚠️ YARA Compilation Error")
        
        # Extract line number for better context
        line_match = re.search(r'line (\d+)', error_msg, re.IGNORECASE)
        if line_match:
            line_num = line_match.group(1)
            msg.setText(f"Compilation failed at line {line_num}")
        else:
            msg.setText("YARA rule compilation failed")
        
        # Clean up error message
        clean_error = error_msg.strip()
        if clean_error.startswith('line ') and ':' in clean_error:
            clean_error = clean_error.split(':', 1)[1].strip()
        
        # Format the error message for better readability
        if len(clean_error) > 250:
            short_msg = clean_error[:250] + "..."
            msg.setInformativeText(f"Error: {short_msg}")
            msg.setDetailedText(f"Complete error message:\n\n{error_msg}")
        else:
            msg.setInformativeText(clean_error)
        
        # Simple styling for better appearance
        msg.setStyleSheet("""
            QMessageBox {
                min-width: 300px;
            }
            QMessageBox QLabel {
                min-width: 280px;
            }
        """)
        
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

    def _show_reset_confirmation_dialog(self):
        """Show a simple reset confirmation dialog"""
        from PySide6.QtWidgets import QMessageBox
        
        reply = QMessageBox.question(
            self, 
            "Reset All", 
            "This will clear ALL data:\n• YARA editor\n• Compilation output\n• Scan results\n• Directory selection\n• All tables and lists\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        return reply
    
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
        """Setup consistent monospace fonts across editor and compilation output."""
        from PySide6.QtGui import QFont

        theme = self.theme_manager.current_theme if hasattr(self, 'theme_manager') else None
        if theme:
            font_family = theme.editor_font_family
            font_size = theme.editor_font_size
        else:
            font_family = "Consolas"
            font_size = 8

        # Apply to YARA editor via its helper
        self.ui.te_yara_editor.setup_font(font_family, font_size)

        # Apply to compilation output
        font = QFont(font_family, font_size)
        if not font.exactMatch():
            font = QFont("Courier New", font_size)
        self.ui.tb_compilation_output.setFont(font)

    def setup_theming(self):
        """Setup theming system and add theme selector to UI"""
        from PySide6.QtWidgets import QCheckBox, QComboBox, QLabel, QHBoxLayout, QWidget, QSpacerItem, QSizePolicy

        # Create theme selector widget
        theme_widget = QWidget()
        theme_layout = QHBoxLayout(theme_widget)
        theme_layout.setContentsMargins(0, 0, 0, 0)

        # Add spacer to push controls to the right
        spacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        theme_layout.addItem(spacer)

        # Vim checkbox
        self.vim_checkbox = QCheckBox("Vim")
        self.vim_checkbox.setToolTip("Enable vim-style keybindings in the editor")
        self.vim_checkbox.toggled.connect(self._on_vim_toggled)
        theme_layout.addWidget(self.vim_checkbox)

        # Vim mode indicator label
        self.vim_mode_label = QLabel("")
        self.vim_mode_label.setStyleSheet("font-weight: bold; margin-left: 4px; margin-right: 8px;")
        theme_layout.addWidget(self.vim_mode_label)

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

        # Connect vim mode display and save/quit signals
        self.ui.te_yara_editor.vim_mode_changed.connect(self._update_vim_mode_display)
        self.ui.te_yara_editor._vim_handler.save_requested.connect(self.on_save_rule)
        self.ui.te_yara_editor._vim_handler.quit_requested.connect(self.close)
    
    def load_theme_settings(self):
        """Load saved theme settings or apply default theme"""
        config_path = Path(__file__).parent / "config" / "settings.json"

        # Default to light theme
        current_theme = "Light"
        vim_enabled = False

        # Try to load saved preferences
        try:
            if config_path.exists():
                import json
                with open(config_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                current_theme = settings.get('theme', 'Light')
                vim_enabled = settings.get('vim_mode', False)
        except Exception as e:
            print(f"Error loading theme settings: {e}")

        # Set theme in combo box and apply
        if current_theme in [self.theme_combo.itemText(i) for i in range(self.theme_combo.count())]:
            self.theme_combo.setCurrentText(current_theme)

        self.apply_theme(current_theme)

        # Restore vim mode setting (after theme is applied)
        self.vim_checkbox.setChecked(vim_enabled)
    
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

    # ─── Vim integration ─────────────────────────────────────────────

    def _on_vim_toggled(self, enabled):
        """Handle vim checkbox toggle."""
        self.ui.te_yara_editor.set_vim_mode(enabled)
        self._save_vim_setting(enabled)

    def _update_vim_mode_display(self, text):
        """Update vim mode indicator label."""
        self.vim_mode_label.setText(text)

    def _save_vim_setting(self, enabled):
        """Persist vim_mode to config/settings.json."""
        config_path = Path(__file__).parent / "config" / "settings.json"
        try:
            settings = {}
            if config_path.exists():
                import json
                with open(config_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
            settings['vim_mode'] = enabled
            import json
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            print(f"Error saving vim setting: {e}")
    
    def apply_theme(self, theme_name):
        """Apply the selected theme to the entire application."""
        theme = self.theme_manager.get_theme(theme_name)
        self.theme_manager.set_current_theme(theme_name)

        stylesheet = self.theme_manager.generate_qss_stylesheet(theme)
        self.setStyleSheet(stylesheet)

        # Pass theme manager to editor for current-line colour etc.
        self.ui.te_yara_editor.set_theme_manager(self.theme_manager)

        self.update_themed_widgets(theme)

        if hasattr(self, 'highlighter') and self.highlighter:
            self.highlighter.update_theme(theme)

        # Propagate theme to open hex editor windows
        if hasattr(self, '_hex_editor_windows'):
            for win in self._hex_editor_windows:
                try:
                    if win.isVisible():
                        win.apply_theme()
                except RuntimeError:
                    pass
    
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
        
        # Update compilation output styling for theme
        self._update_compilation_output_theme(theme)
        
        # Update checkbox icons with theme colors
        self.update_checkbox_icons(theme)
        
        # Update editor fonts with theme font settings
        self._setup_monospace_fonts()
        
        # Force text editor selection colors using palette
        self._update_text_editor_palette(theme)

    def _update_compilation_output_theme(self, theme):
        """Update compilation output styling based on current theme"""
        colors = theme.colors
        
        # Apply theme-appropriate styling to compilation output
        compilation_output_style = f"""
        QTextBrowser {{
            background-color: {colors.editor_background};
            color: {colors.editor_text};
            border: 1px solid {colors.editor_background};
            selection-background-color: {colors.editor_selection};
            selection-color: {colors.editor_text};
        }}
        """
        
        self.ui.tb_compilation_output.setStyleSheet(compilation_output_style)

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
            
            # Mark document as not modified (just loaded from file)
            self._last_saved_text = text
            self._document_modified = False

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
            # Mark document as saved
            self._last_saved_text = text
            self._document_modified = False
            self.statusBar().showMessage(f"YARA rule saved: {path}", 4000)
        except Exception as e:
            QMessageBox.critical(self, "Save failed", f"Could not save file:\n{e}")

    def on_reset(self):
        """Reset everything to a completely fresh start"""
        reply = self._show_reset_confirmation_dialog()
        
        if reply == QMessageBox.StandardButton.Yes:
            # Clear YARA editor and compilation
            self.ui.te_yara_editor.clear()
            self.compiled_rules = None
            
            # Clear all scan data
            self.scan_hits = []
            self.scan_misses = []
            self.scan_root = None

            # Clear all results views
            self.results.clear_all()
            
            # Clear exclusion list
            self.ui.listWidget.clear()
            
            # Reset directory tree
            self.fs_view.setRootIndex(QModelIndex())  # Empty tree
            self.fs_model._unchecked.clear()  # Clear exclusions
            
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
            
            # Reset all tab focus to default states
            # Main tabs: Focus on Scan Dir tab (index 0)
            self.ui.tabWidget.setCurrentIndex(0)  # Switch to Scan Dir tab
            
            # Scan Results sub-tabs: Focus on Hits tab (index 0) 
            if hasattr(self.ui, 'tabWidget_2'):
                self.ui.tabWidget_2.setCurrentIndex(0)  # Focus on Hits tab
            
            # Details sub-tabs: Focus on Rule Details tab (index 0)
            if hasattr(self.ui, 'tabWidget_3'):
                self.ui.tabWidget_3.setCurrentIndex(0)  # Focus on Rule Details tab
            
            # Match Details tabs: If there are match details sub-tabs, focus on default
            if hasattr(self.ui, 'tabWidget_4'):  # In case there's a 4th level of tabs
                self.ui.tabWidget_4.setCurrentIndex(0)
            
            self.statusBar().showMessage("Complete reset - ready for fresh start", 5000)

    def on_format_yara(self) -> None:
        """Format the YARA rule in the editor using yara-x Formatter."""
        text = self.ui.te_yara_editor.toPlainText()
        
        if not text.strip():
            QMessageBox.information(self, "No Content", "No YARA rule to format.")
            return
        
        # Try yara-x formatter first, fall back to yaraast if needed
        if YARA_X_AVAILABLE:
            try:
                formatted_text = self.scanner.format_with_yara_x(text)
                self._load_text_to_editor(formatted_text)
                self.statusBar().showMessage("YARA rule formatted with yara-x", 3000)
                return
            except Exception as e:
                QMessageBox.warning(self, "Cannot Format Rule",
                                   f"Unable to format YARA rule with yara-x:\n\n{str(e)}\n\n"
                                   "Please fix the syntax errors first, then try formatting again.")
                self.statusBar().showMessage(f"yara-x formatting failed: {str(e)[:50]}...", 5000)
                return

        # Fallback to yaraast if yara-x is not available
        if YARAAST_AVAILABLE:
            try:
                formatted_text = self.scanner.format_with_ast(text)
                self._load_text_to_editor(formatted_text)
                self.statusBar().showMessage("YARA rule formatted with yaraast fallback", 3000)
            except Exception as e:
                QMessageBox.warning(self, "Cannot Format Rule",
                                   f"Unable to format YARA rule due to syntax errors:\n\n{str(e)}\n\n"
                                   "Please fix the syntax errors first, then try formatting again.")
                self.statusBar().showMessage(f"Formatting failed: {str(e)[:50]}...", 5000)
        else:
            QMessageBox.warning(self, "No Formatter Available",
                               "Neither yara-x nor yaraast is available for formatting. Please install one of them.")
            return

    def on_scan(self) -> None:
        """Scan selected files with compiled YARA rules (runs on a worker thread).

        While a scan is in progress, the SCAN button flips to CANCEL, so
        clicking it a second time requests a graceful stop instead of
        starting a new scan.
        """
        # If a scan is already running, the SCAN button acts as CANCEL.
        if self._scan_worker is not None and self._scan_worker.isRunning():
            self._on_scan_cancel_clicked()
            return

        if not self._validate_scan_prerequisites():
            return

        rule_text = self.ui.te_yara_editor.toPlainText()

        # Compile rules first (fast — stays on main thread)
        compiled_rules = self._compile_yara_rules(rule_text)
        if not compiled_rules:
            return

        # Prepare for scanning
        self._prepare_scan_ui()

        # Collect files to scan
        files_to_scan = list(self.iter_selected_files())
        if not files_to_scan:
            self.ui.tb_compilation_output.append("\u26a0 No files to scan (all excluded or empty directory).")
            self.statusBar().showMessage("No files to scan", 3000)
            return

        # Derive filesize bounds from the rule text so the worker can
        # skip files that can't possibly match without reading them.
        size_bounds = self._compute_size_bounds(rule_text)

        # Kick off the worker thread — returns immediately.
        # Results are handled in _on_scan_finished.
        self._perform_file_scanning(compiled_rules, files_to_scan, size_bounds)

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
            
            rules = self.scanner.compile_rules(rule_text)
            
            # Format success message nicely with theme-aware colors
            theme_colors = self._get_theme_colors_for_output()
            success_bg = "rgba(76, 175, 80, 0.2)" if "dark" in getattr(self.theme_manager.current_theme, 'name', '').lower() else "rgba(76, 175, 80, 0.1)"
            
            success_msg = f'''
            <div style="border-left: 4px solid #4caf50; padding: 8px 12px; margin: 4px 0; background-color: {success_bg};">
                <div style="color: #4caf50; font-weight: bold; margin-bottom: 4px;">
                    ✅ Compilation Successful <span style="color: {theme_colors["secondary_text"]}; font-size: 11px;">[{timestamp}]</span>
                </div>
                <div style="color: {theme_colors["main_text"]}; font-size: 13px;">
                    YARA rules compiled and ready for scanning
                </div>
            </div>
            '''
            self.ui.tb_compilation_output.append(success_msg)
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
        self.results.clear_all()
    
    def _compute_size_bounds(self, rule_text: str):
        """Parse the rule text for `filesize` constraints and log the
        derived skip bounds (if any) to the compilation output."""
        from scanner import compute_size_bounds, format_size
        bounds = compute_size_bounds(rule_text)
        if bounds.is_useful():
            parts = []
            if bounds.min_size > 0:
                parts.append(f"min={format_size(bounds.min_size)}")
            if bounds.max_size is not None:
                parts.append(f"max={format_size(bounds.max_size)}")
            self.ui.tb_compilation_output.append(
                f"\u26A1 filesize pre-filter active: {', '.join(parts)} "
                f"\u2014 files outside this range will be skipped "
                f"without being read."
            )
        return bounds

    def _perform_file_scanning(self, rules, files_to_scan: List[Path],
                                size_bounds=None) -> None:
        """Launch the background scan worker; results land in ``_on_scan_finished``."""
        total = len(files_to_scan)
        self.ui.tb_compilation_output.append(f"Scanning {total} files...\n")
        self.statusBar().showMessage(f"Scanning {total} files...", 0)

        # Show progress bar + cancel button in status bar
        self._scan_progress.setRange(0, total)
        self._scan_progress.setValue(0)
        self._scan_progress.setFormat("Scanning %v / %m  (%p%)")
        self._scan_progress.show()
        self._scan_cancel_btn.setEnabled(True)
        self._scan_cancel_btn.show()

        # Flip the SCAN button into a CANCEL button so the user has an
        # obvious way to stop a runaway scan (e.g. accidentally scanning
        # a folder full of 2 GB files). The click handler already checks
        # for a running worker and routes to cancel in that case.
        if not hasattr(self, "_scan_btn_default_text"):
            self._scan_btn_default_text = self.ui.pb_scan.text()
            self._scan_btn_default_tooltip = self.ui.pb_scan.toolTip()
        self.ui.pb_scan.setText("\u26D4 CANCEL SCAN")
        self.ui.pb_scan.setToolTip("Cancel the running scan")
        self.ui.pb_scan.setEnabled(True)

        # Spin up the worker thread
        self._scan_worker = ScanWorker(
            self.scanner, rules, files_to_scan, parent=self,
            size_bounds=size_bounds,
        )
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.result_ready.connect(self._on_scan_finished)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.finished.connect(self._on_scan_thread_done)
        self._scan_worker.start()

    def _on_scan_progress(self, scanned: int, total: int, filename: str) -> None:
        """Worker thread → main thread progress update."""
        self._scan_progress.setValue(scanned)
        # Truncate very long filenames so the status bar stays readable
        display = filename if len(filename) <= 60 else filename[:57] + "..."
        self.statusBar().showMessage(
            f"Scanning ({scanned}/{total}): {display}", 0)

    def _on_scan_finished(self, result: dict) -> None:
        """Worker finished (successfully or cancelled). Populate results into UI."""
        # Process hits
        for hit in result['hits']:
            self.scan_hits.append(hit)
            self._add_hit_to_table(hit['filename'], hit['filepath'], hit['matched_rules'])

        # Stash misses (displayed lazily via the tab-change hook)
        for miss in result['misses']:
            self.scan_misses.append(miss)

        # Surface per-file errors
        for msg in result['error_messages']:
            self.ui.tb_compilation_output.append(f"\n{msg}")

        cancelled = bool(result.get('cancelled'))
        stats = result['stats']
        if cancelled:
            self.ui.tb_compilation_output.append(
                f"\n\u26a0 Scan cancelled after {stats['scanned']} file(s)."
            )
            self.statusBar().showMessage(
                f"Scan cancelled \u2014 {stats['scanned']} scanned, "
                f"{stats['matches']} matches",
                6000
            )

        # Finalize (populate aggregate views, switch tabs, show summary)
        self._finalize_scan_results(stats)

    def _on_scan_error(self, msg: str) -> None:
        """Fatal worker-thread error."""
        self.ui.tb_compilation_output.append(f"\n\u2717 {msg}")
        self.statusBar().showMessage("Scan failed", 5000)

    def _on_scan_thread_done(self) -> None:
        """Hide progress widgets and drop the worker reference (UI thread)."""
        self._scan_progress.hide()
        self._scan_cancel_btn.hide()
        # Restore the SCAN button label/tooltip (it was swapped to CANCEL
        # for the duration of the scan).
        if hasattr(self, "_scan_btn_default_text"):
            self.ui.pb_scan.setText(self._scan_btn_default_text)
            self.ui.pb_scan.setToolTip(self._scan_btn_default_tooltip)
        self.ui.pb_scan.setEnabled(True)
        # Let Qt clean up the QThread before releasing our reference
        if self._scan_worker is not None:
            self._scan_worker.deleteLater()
            self._scan_worker = None

    def _on_scan_cancel_clicked(self) -> None:
        """User clicked cancel (either the status-bar button or the main
        SCAN/CANCEL button in the toolbar)."""
        if self._scan_worker is None or not self._scan_worker.isRunning():
            return
        self._scan_worker.cancel()
        self._scan_cancel_btn.setEnabled(False)
        # Gray out the main button and update its label so the user gets
        # immediate feedback while the current file finishes scanning.
        self.ui.pb_scan.setEnabled(False)
        self.ui.pb_scan.setText("Cancelling...")
        self.statusBar().showMessage(
            "Cancelling scan \u2014 finishing current file...", 0)
    
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
        
        self.results.hits_model.appendRow([filename_item, filepath_item])
    
    def _finalize_scan_results(self, stats: Dict[str, int]) -> None:
        """Finalize scan results and update UI."""
        # Format table
        self.results._force_thin_rows(self.ui.tv_file_hits)
        self.ui.tv_file_hits.resizeColumnToContents(0)

        # Switch to results tab
        self.ui.tabWidget.setCurrentIndex(1)
        self.ui.tabWidget_2.setCurrentIndex(0)

        # Populate additional views
        self.results.populate_similar_files(self.scan_hits)
        self.results.initialize_similar_tags_widget()
        self.results.populate_match_details(self.scan_hits)

        # Show summary
        self._display_scan_summary(stats)

    def _display_scan_summary(self, stats: Dict[str, int]) -> None:
        """Display scan completion summary."""
        self.ui.tb_compilation_output.append("\n=== Scan Complete ===")
        self.ui.tb_compilation_output.append(f"Files scanned: {stats['scanned']}")
        self.ui.tb_compilation_output.append(f"Matches found: {stats['matches']}")
        self.ui.tb_compilation_output.append(f"Files without matches: {len(self.scan_misses)}")

        skipped = stats.get('skipped', 0)
        if skipped > 0:
            self.ui.tb_compilation_output.append(
                f"\u26A1 Skipped via filesize pre-filter: {skipped} "
                f"(outside rule bounds \u2014 not read from disk)"
            )

        if stats['errors'] > 0:
            self.ui.tb_compilation_output.append(f"Errors: {stats['errors']}")

        if stats['matches'] > 0:
            self.ui.tb_compilation_output.append(f"\n✓ Results populated in Scan Results tab")
            
            # Populate all views immediately after scan completion
            if self.scan_hits:
                all_filepaths = {h['filepath'] for h in self.scan_hits}
                self.results.populate_rule_details(self.scan_hits)
                self.results.populate_similar_files(self.scan_hits, all_filepaths)
                self.results.populate_similar_tags(self.scan_hits, all_filepaths)
                self.results.populate_match_details(self.scan_hits)
        else:
            self.ui.tb_compilation_output.append(f"\n✓ No threats detected - all files clean")

        self.statusBar().showMessage(
            f"Scan complete: {stats['scanned']} files, {stats['matches']} matches",
            10000
        )

    # ── scan-dir filter bar ──────────────────────────────────────
    def _build_fs_filter_bar(self, parent: QWidget) -> QWidget:
        """Build the filter row that sits above the file-system tree.

        The filter can match by glob (default) or Python regex, against
        either the file name or the full path. The four action buttons
        operate on the current scan root:

        * Select matching only - keep only matching files (everything
          else becomes excluded).
        * Exclude matching     - add matching files to the exclusion
          list (additive: keeps existing exclusions intact).
        * Select all           - clear all exclusions.
        * Deselect all         - exclude the entire scan root.

        All long-running traversals run with a busy cursor.
        """
        bar = QWidget(parent)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        layout.addWidget(QLabel("Filter:"))

        self.fs_filter_edit = QLineEdit(bar)
        self.fs_filter_edit.setPlaceholderText(
            "*.exe,*.dll   or   \\.(exe|dll)$")
        self.fs_filter_edit.setClearButtonEnabled(True)
        self.fs_filter_edit.setToolTip(
            "Glob: comma-separated patterns (e.g. *.exe,*.dll).\n"
            "Regex: Python re syntax. Case-insensitive.")
        self.fs_filter_edit.returnPressed.connect(
            self._on_fs_select_matching_only)
        layout.addWidget(self.fs_filter_edit, 1)

        self.fs_filter_mode = QComboBox(bar)
        self.fs_filter_mode.addItems(["Glob", "Regex"])
        self.fs_filter_mode.setToolTip("How to interpret the filter text")
        layout.addWidget(self.fs_filter_mode)

        self.fs_filter_target = QComboBox(bar)
        self.fs_filter_target.addItems(["Name", "Full path"])
        self.fs_filter_target.setToolTip(
            "Match against the file name only, or the full path")
        layout.addWidget(self.fs_filter_target)

        btn_keep = QPushButton("Select matching only", bar)
        btn_keep.setToolTip(
            "Clear exclusions, then exclude every file that does NOT "
            "match the filter")
        btn_keep.clicked.connect(self._on_fs_select_matching_only)
        layout.addWidget(btn_keep)

        btn_excl = QPushButton("Exclude matching", bar)
        btn_excl.setToolTip(
            "Add every file that matches the filter to the exclusion "
            "list (keeps existing exclusions)")
        btn_excl.clicked.connect(self._on_fs_exclude_matching)
        layout.addWidget(btn_excl)

        btn_all = QPushButton("Select all", bar)
        btn_all.setToolTip("Clear all exclusions")
        btn_all.clicked.connect(self._on_fs_select_all)
        layout.addWidget(btn_all)

        btn_none = QPushButton("Deselect all", bar)
        btn_none.setToolTip("Exclude the entire scan root")
        btn_none.clicked.connect(self._on_fs_deselect_all)
        layout.addWidget(btn_none)

        return bar

    def _fs_filter_predicate(self):
        """Build a ``match(name, full_path) -> bool`` callable from the
        current filter bar state.

        Returns ``None`` if the filter text is empty or if the pattern
        is invalid (status bar receives an explanatory message in the
        latter case).
        """
        text = self.fs_filter_edit.text().strip()
        if not text:
            return None

        mode = self.fs_filter_mode.currentText()
        target = self.fs_filter_target.currentText()
        use_full_path = target == "Full path"

        if mode == "Regex":
            try:
                pat = re.compile(text, re.IGNORECASE)
            except re.error as e:
                self.statusBar().showMessage(f"Bad regex: {e}", 5000)
                return None

            def match(name: str, full_path: str) -> bool:
                return pat.search(full_path if use_full_path else name) is not None

            return match

        # Glob: comma-separated list, case-insensitive (fnmatch on Windows
        # is already case-insensitive via fnmatch.fnmatch, but we force
        # lowercase to behave the same everywhere).
        patterns = [p.strip() for p in text.split(",") if p.strip()]
        if not patterns:
            return None
        lowered = [p.lower() for p in patterns]

        def match(name: str, full_path: str) -> bool:
            subject = (full_path if use_full_path else name).lower()
            for pat in lowered:
                if fnmatch.fnmatchcase(subject, pat):
                    return True
            return False

        return match

    def _fs_require_scan_root(self) -> bool:
        if self.scan_root is None:
            self.statusBar().showMessage(
                "Select a scan directory first", 4000)
            return False
        return True

    def _fs_refresh_view(self) -> None:
        """Refresh the tree and exclusion list after bulk changes to
        ``_unchecked`` (direct mutation bypasses :meth:`setData`)."""
        root_idx = self.fs_view.rootIndex()
        if root_idx.isValid():
            self.fs_model._update_visible_children(root_idx)
        self.update_exclusion_list()
        self.fs_model.exclusionsChanged.emit()

    def _on_fs_select_all(self) -> None:
        if not self._fs_require_scan_root():
            return
        self.fs_model._unchecked.clear()
        self._fs_refresh_view()
        self.statusBar().showMessage("All files selected", 3000)

    def _on_fs_deselect_all(self) -> None:
        if not self._fs_require_scan_root():
            return
        root = self.fs_model._normalize_path(str(self.scan_root))
        self.fs_model._unchecked.clear()
        self.fs_model._unchecked.add(root)
        self._fs_refresh_view()
        self.statusBar().showMessage("All files deselected", 3000)

    def _on_fs_exclude_matching(self) -> None:
        if not self._fs_require_scan_root():
            return
        match = self._fs_filter_predicate()
        if match is None:
            if not self.fs_filter_edit.text().strip():
                self.statusBar().showMessage(
                    "Enter a filter pattern first", 4000)
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            added = 0
            normalize = self.fs_model._normalize_path
            unchecked = self.fs_model._unchecked
            for root, dirs, files in os.walk(self.scan_root):
                for name in files:
                    full = os.path.join(root, name)
                    if match(name, full):
                        norm = normalize(full)
                        if norm not in unchecked:
                            unchecked.add(norm)
                            added += 1
        finally:
            QApplication.restoreOverrideCursor()

        self._fs_refresh_view()
        self.statusBar().showMessage(
            f"Excluded {added} matching file(s)", 5000)

    def _on_fs_select_matching_only(self) -> None:
        """Clear exclusions, then exclude everything that does not match
        the filter.

        Uses a two-pass walk:

        1. Bottom-up: count matching files per directory subtree.
        2. Top-down: directories whose subtree has zero matches are
           excluded wholesale (a single entry in ``_unchecked``).
           Directories with matches are descended into, and each file
           there is individually excluded if it doesn't match.

        This keeps ``_unchecked`` small even for very large trees.
        """
        if not self._fs_require_scan_root():
            return
        match = self._fs_filter_predicate()
        if match is None:
            if not self.fs_filter_edit.text().strip():
                self.statusBar().showMessage(
                    "Enter a filter pattern first", 4000)
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            # Pass 1: collect (dir_path, [matching_files], [non_matching_files])
            # and match counts per directory using a single os.walk.
            # match_count[dir] = number of matching files in dir's subtree.
            match_count: Dict[str, int] = {}
            dir_files: Dict[str, List[tuple]] = {}
            dir_order: List[str] = []  # parents before children (os.walk default)
            for root, dirs, files in os.walk(self.scan_root):
                dir_order.append(root)
                local = []
                local_matches = 0
                for name in files:
                    full = os.path.join(root, name)
                    is_match = match(name, full)
                    local.append((name, full, is_match))
                    if is_match:
                        local_matches += 1
                dir_files[root] = local
                match_count[root] = local_matches

            # Propagate counts up: walk dir_order in reverse so children
            # aggregate into parents before parents are themselves read.
            for d in reversed(dir_order):
                parent = os.path.dirname(d)
                if parent in match_count and parent != d:
                    match_count[parent] += match_count[d]

            # Pass 2: start fresh, then exclude empty branches wholesale
            # and individual non-matching files in live branches.
            unchecked = set()
            normalize = self.fs_model._normalize_path
            total_matches = match_count.get(str(self.scan_root), 0)

            skipped_dirs: List[str] = []  # prefixes we've already excluded
            for d in dir_order:
                # If an ancestor was already excluded, skip quickly.
                if any(d == s or d.startswith(s + os.sep)
                       for s in skipped_dirs):
                    continue
                if match_count.get(d, 0) == 0:
                    # Entire subtree has no matches - exclude the dir
                    unchecked.add(normalize(d))
                    skipped_dirs.append(d)
                    continue
                # Live branch: exclude non-matching files individually.
                for name, full, is_match in dir_files[d]:
                    if not is_match:
                        unchecked.add(normalize(full))

            self.fs_model._unchecked = unchecked
        finally:
            QApplication.restoreOverrideCursor()

        self._fs_refresh_view()
        self.statusBar().showMessage(
            f"Kept {total_matches} matching file(s)", 5000)

    def on_select_scan_dir(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select folder to scan", self.last_dir,
            options=QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks,
        )
        if not path:
            return
        self._set_scan_root(Path(path))

    def _set_scan_root(self, path: Path) -> None:
        """Set *path* as the current scan directory and refresh the tree.

        Shared by the File menu, drag/drop, and command-line handling.
        """
        path = Path(path).resolve()
        if not path.is_dir():
            self.statusBar().showMessage(
                f"Not a directory: {path}", 4000)
            return

        self.scan_root = path
        self.last_dir = str(path)

        root_idx = self.fs_model.setRootPath(str(path))

        # Connect model to view if not already connected (first directory selection)
        if self.fs_view.model() is None:
            self.fs_view.setModel(self.fs_model)

        # Process events to allow the file system model to populate
        QApplication.processEvents()

        self.fs_view.setRootIndex(root_idx)
        self.fs_view.expand(root_idx)

        # Process events again after expanding
        QApplication.processEvents()

        self.statusBar().showMessage(
            f"Selected root: {path} (all files selected by default)", 4000)
        self.update_exclusion_list()

        # Focus on the file tree tab
        self.ui.tabWidget.setCurrentWidget(self.ui.tab_scan_dir)

    def _handle_input_paths(self, paths) -> None:
        """Dispatch a list of path-like inputs from drag/drop or the CLI.

        Dispatch rules:
        * Directory  -> set as scan root (first dropped dir wins if many)
        * .yar/.yara -> loaded into the YARA rule editor
        * other file -> opened in a new hex editor window
        Missing paths are silently ignored.
        """
        resolved = []
        for p in paths:
            try:
                pp = Path(p)
            except TypeError:
                continue
            if pp.exists():
                resolved.append(pp)
        if not resolved:
            return

        dirs = [p for p in resolved if p.is_dir()]
        files = [p for p in resolved if p.is_file()]

        if dirs:
            self._set_scan_root(dirs[0])
            if len(dirs) > 1:
                self.statusBar().showMessage(
                    f"Multiple folders dropped \u2014 using "
                    f"'{dirs[0].name}' as scan root", 5000)

        for fp in files:
            ext = fp.suffix.lower()
            if ext in (".yar", ".yara", ".yarax"):
                try:
                    text = fp.read_text(encoding="utf-8")
                    self._load_text_to_editor(text, source_path=str(fp))
                except Exception as e:
                    self.statusBar().showMessage(
                        f"Failed to load {fp.name}: {e}", 5000)
            else:
                self.open_hex_editor(str(fp))

    # ── drag & drop plumbing ─────────────────────────────────────
    @staticmethod
    def _drop_urls(event) -> list:
        md = event.mimeData()
        if not md or not md.hasUrls():
            return []
        out = []
        for u in md.urls():
            if u.isLocalFile():
                lf = u.toLocalFile()
                if lf:
                    out.append(lf)
        return out

    def dragEnterEvent(self, event) -> None:
        if self._drop_urls(event):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        if self._drop_urls(event):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        paths = self._drop_urls(event)
        if not paths:
            event.ignore()
            return
        event.acceptProposedAction()
        self._handle_input_paths(paths)

    def eventFilter(self, obj, event):
        """Intercept URL drops on child widgets that would otherwise
        swallow them (QPlainTextEdit, QTreeView)."""
        et = event.type()
        if et in (QEvent.DragEnter, QEvent.DragMove):
            if self._drop_urls(event):
                event.acceptProposedAction()
                return True
        elif et == QEvent.Drop:
            paths = self._drop_urls(event)
            if paths:
                event.acceptProposedAction()
                self._handle_input_paths(paths)
                return True
        return super().eventFilter(obj, event)

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
        """Handle tab changes in scan results - lazy load misses when needed."""
        if index == 1 and not self.results.misses_loaded:
            self.results.populate_misses_tab(self.scan_misses)

    def on_hits_selection_changed(self, selected, deselected):
        """Handle selection changes in hits table to show details for all selected files."""
        if self._updating_selection:
            return

        selection_model = self.ui.tv_file_hits.selectionModel()
        selected_indexes = selection_model.selectedRows()

        if not selected_indexes:
            if self.scan_hits:
                all_filepaths = {h['filepath'] for h in self.scan_hits}
                self.results.populate_rule_details(self.scan_hits)
                self.results.populate_similar_files(self.scan_hits, all_filepaths)
                self.results.populate_similar_tags(self.scan_hits, all_filepaths)
                self.results.populate_match_details(self.scan_hits)
            else:
                self.results.clear_rule_details()
                self.results.clear_similar_files()
                self.results.clear_match_details()
            return

        selected_hits = []
        for index in selected_indexes:
            source_index = self.results.hits_proxy.mapToSource(index)
            row = source_index.row()
            filepath_item = self.results.hits_model.item(row, 1)
            if not filepath_item:
                continue
            filepath = filepath_item.text()
            for hit in self.scan_hits:
                if hit.get('filepath') == filepath:
                    selected_hits.append(hit)
                    break

        if selected_hits:
            selected_filepaths = {h['filepath'] for h in selected_hits}
            self.results.populate_rule_details(selected_hits)
            self.results.populate_similar_files(self.scan_hits, selected_filepaths)
            self.results.populate_match_details(selected_hits)
            self.results.populate_similar_tags(self.scan_hits, selected_filepaths)


    def _on_file_selection_requested(self, identifier: str):
        """Handle file selection request from results manager (filepath or filename)."""
        if self._updating_selection:
            return
        self._updating_selection = True
        try:
            # Try exact filepath match first
            for source_row, hit_data in enumerate(self.scan_hits):
                if hit_data['filepath'] == identifier:
                    source_index = self.results.hits_model.index(source_row, 0)
                    proxy_index = self.results.hits_proxy.mapFromSource(source_index)
                    if proxy_index.isValid():
                        self.ui.tv_file_hits.selectRow(proxy_index.row())
                    selected_hits = [hit_data]
                    selected_filepaths = {hit_data['filepath']}
                    self.results.populate_rule_details(selected_hits)
                    self.results.populate_similar_files(self.scan_hits, selected_filepaths)
                    self.results.populate_match_details(selected_hits)
                    self.results.populate_similar_tags(self.scan_hits, selected_filepaths)
                    self.statusBar().showMessage(
                        f"Selected: {hit_data['filename']} | {len(hit_data.get('matched_rules', []))} rule(s) | Path: {identifier}",
                        8000
                    )
                    return
            # Fallback: try filename match
            for source_row, hit_data in enumerate(self.scan_hits):
                if hit_data['filename'] == identifier:
                    source_index = self.results.hits_model.index(source_row, 0)
                    proxy_index = self.results.hits_proxy.mapFromSource(source_index)
                    if proxy_index.isValid():
                        self.ui.tv_file_hits.selectRow(proxy_index.row())
                    selected_hits = [hit_data]
                    selected_filepaths = {hit_data['filepath']}
                    self.results.populate_rule_details(selected_hits)
                    self.results.populate_similar_files(self.scan_hits, selected_filepaths)
                    self.results.populate_match_details(selected_hits)
                    self.results.populate_similar_tags(self.scan_hits, selected_filepaths)
                    return
        finally:
            self._updating_selection = False

    # ─── Hex editor ───────────────────────────────────────────────────

    def open_hex_editor(self, filepath: str = None, offset: int = 0, length: int = 0):
        """Open a hex editor window.

        *filepath* can be a full path or just a filename.  When called from
        the match-details context menu it is a filename, so we resolve it
        against scan_hits.  *length* selects that many bytes at *offset*.
        """
        # Clean up closed/deleted windows
        def _alive(w):
            try:
                return w.isVisible()
            except RuntimeError:
                return False
        self._hex_editor_windows = [w for w in self._hex_editor_windows if _alive(w)]

        # Resolve filename -> filepath via scan_hits and misses
        if filepath and not Path(filepath).exists():
            for hit in self.scan_hits:
                if hit.get('filename') == filepath or hit.get('filepath') == filepath:
                    filepath = hit['filepath']
                    break
            else:
                for miss in self.scan_misses:
                    if miss.get('filename') == filepath or miss.get('filepath') == filepath:
                        filepath = miss['filepath']
                        break

        win = HexEditorWindow(theme_manager=self.theme_manager, parent=None)
        win.yara_pattern_generated.connect(self._insert_yara_pattern)
        self._hex_editor_windows.append(win)

        if filepath and Path(filepath).exists():
            win.show()
            win.open_file(filepath, offset, length)
        else:
            win.show()
            win._on_open()
            return

        win.show()

    def _insert_yara_pattern(self, pattern_text: str):
        """Insert a YARA hex pattern from the hex editor at the current cursor position."""
        cursor = self.ui.te_yara_editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.EndOfLine)
        cursor.insertText("\n    " + pattern_text)
        self.ui.te_yara_editor.setTextCursor(cursor)
        self.ui.te_yara_editor.ensureCursorVisible()
        self.statusBar().showMessage("YARA pattern inserted from hex editor", 5000)

    def _show_fs_context_menu(self, pos):
        """Show context menu for the file system tree view."""
        index = self.fs_view.indexAt(pos)
        if not index.isValid():
            return

        filepath = self.fs_model.filePath(index)
        if not filepath or not Path(filepath).is_file():
            return

        menu = QMenu(self)
        hex_action = menu.addAction("Open in Hex Editor")
        action = menu.exec(self.fs_view.viewport().mapToGlobal(pos))
        if action == hex_action:
            self.open_hex_editor(filepath)

    def _show_hits_context_menu(self, pos):
        """Show context menu for file hits table."""
        index = self.ui.tv_file_hits.indexAt(pos)
        if not index.isValid():
            return

        source_index = self.results.hits_proxy.mapToSource(index)
        row = source_index.row()
        filepath_item = self.results.hits_model.item(row, 1)
        if not filepath_item:
            return
        filepath = filepath_item.text()

        menu = QMenu(self)
        hex_action = menu.addAction("Open in Hex Editor")
        action = menu.exec(self.ui.tv_file_hits.viewport().mapToGlobal(pos))
        if action == hex_action:
            self.open_hex_editor(filepath)

    def highlight_tag_in_editor(self, tag_name):
        """Highlight the specified tag in the YARA editor."""
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
    

if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = MainWindow()
    widget.show()

    # Handle command-line arguments (file association / drag onto .exe /
    # Open-With). Same dispatcher as drag-and-drop onto the running window:
    #   directory -> scan root
    #   .yar/.yara -> YARA rule editor
    #   any other file -> hex editor
    if len(sys.argv) > 1:
        widget._handle_input_paths(sys.argv[1:])

    sys.exit(app.exec())
