# This Python file uses the following encoding: utf-8

"""
ScanResultsManager - Manages scan results population, navigation, and display.

Handles hits/misses tables, rule details, similar files/tags, and match details.
Deduplicates near-identical single/multi-selection methods into unified APIs.
"""

from typing import Dict, List, Optional, Set

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (QAbstractItemView, QHeaderView, QMenu,
                               QTableWidgetItem, QTreeWidgetItem)

from search_filter import (DebouncedSearchBar, MultiColumnFilterProxy,
                           filter_table_widget, filter_tree_widget,
                           inject_search_bar)


class ScanResultsManager(QObject):
    """Manages all scan result population, navigation, and display logic."""

    # Signals for callbacks to MainWindow
    file_selection_requested = Signal(str)       # filepath -> MainWindow selects in hits table
    tag_highlight_requested = Signal(str)        # tag_name -> MainWindow highlights in editor
    status_message_requested = Signal(str, int)  # message, timeout -> MainWindow statusBar
    hex_editor_requested = Signal(str, int, int)  # filepath, offset, length -> MainWindow opens hex editor

    def __init__(self, ui, theme_manager, parent=None):
        """
        Args:
            ui: The Ui_MainWindow instance (for widget access)
            theme_manager: The theme manager instance (for column colors)
        """
        super().__init__(parent)
        self.ui = ui
        self.theme_manager = theme_manager

        # Models owned by this manager
        self.hits_model = QStandardItemModel()
        self.hits_model.setHorizontalHeaderLabels(['File', 'Path'])

        self.misses_model = QStandardItemModel()
        self.misses_model.setHorizontalHeaderLabels(['File', 'Path'])

        self.rule_details_model = QStandardItemModel()
        self.rule_details_model.setHorizontalHeaderLabels(['Property', 'Value'])

        # Proxy models for filtered views
        self.hits_proxy = MultiColumnFilterProxy(parent=self)
        self.hits_proxy.setSourceModel(self.hits_model)
        self.misses_proxy = MultiColumnFilterProxy(parent=self)
        self.misses_proxy.setSourceModel(self.misses_model)
        self.rule_details_proxy = MultiColumnFilterProxy(parent=self)
        self.rule_details_proxy.setSourceModel(self.rule_details_model)

        # Search bars (populated in setup_scan_results_ui)
        self._search_bars = {}

        self.misses_loaded = False

    def setup_scan_results_ui(self):
        """Setup models and connections for scan results."""
        # --- Hits table ---
        self.ui.tv_file_hits.setModel(self.hits_proxy)
        self.ui.tv_file_hits.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.ui.tv_file_hits.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ui.tv_file_hits.setSortingEnabled(True)
        self._make_table_compact(self.ui.tv_file_hits)

        hits_header = self.ui.tv_file_hits.horizontalHeader()
        hits_header.setStretchLastSection(True)
        hits_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        hits_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        hits_header.setDefaultSectionSize(150)
        hits_header.setMinimumSectionSize(80)
        self.ui.tv_file_hits.setWordWrap(False)
        self.ui.tv_file_hits.setTextElideMode(Qt.TextElideMode.ElideMiddle)

        # --- Misses table ---
        self.ui.tv_file_misses.setModel(self.misses_proxy)
        self._make_table_compact(self.ui.tv_file_misses)
        self.ui.tv_file_misses.setSortingEnabled(True)

        misses_header = self.ui.tv_file_misses.horizontalHeader()
        misses_header.setStretchLastSection(True)
        misses_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        misses_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        misses_header.setDefaultSectionSize(150)
        misses_header.setMinimumSectionSize(80)
        self.ui.tv_file_misses.setWordWrap(False)
        self.ui.tv_file_misses.setTextElideMode(Qt.TextElideMode.ElideMiddle)

        # Context menu for misses: "Open in Hex Editor"
        self.ui.tv_file_misses.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ui.tv_file_misses.customContextMenuRequested.connect(self._show_misses_context_menu)

        # --- Rule details table ---
        self.ui.tv_rule_details.setModel(self.rule_details_proxy)
        self._make_table_compact(self.ui.tv_rule_details)

        rule_details_header = self.ui.tv_rule_details.horizontalHeader()
        rule_details_header.setStretchLastSection(True)
        rule_details_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        rule_details_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        rule_details_header.setDefaultSectionSize(150)
        rule_details_header.setMinimumSectionSize(80)
        self.ui.tv_rule_details.setColumnWidth(0, 150)

        # --- Similar files tree ---
        self.ui.tw_similar_files.setHeaderLabels(['File/Rule', 'Info'])
        self.ui.tw_similar_files.setAlternatingRowColors(True)
        self.ui.tw_similar_files.setRootIsDecorated(True)
        self.ui.tw_similar_files.setItemsExpandable(True)
        self.ui.tw_similar_files.setSortingEnabled(True)
        self.ui.tw_similar_files.itemDoubleClicked.connect(self.on_similar_file_double_clicked)
        self._make_tree_compact(self.ui.tw_similar_files)

        # --- Similar tags tree ---
        if hasattr(self.ui, 'tw_similar_tags'):
            self.ui.tw_similar_tags.setHeaderLabels(['Tag/File', 'Details'])
            self.ui.tw_similar_tags.setAlternatingRowColors(True)
            self.ui.tw_similar_tags.setRootIsDecorated(True)
            self.ui.tw_similar_tags.setItemsExpandable(True)
            self.ui.tw_similar_tags.setSortingEnabled(True)
            self.ui.tw_similar_tags.itemDoubleClicked.connect(self.on_similar_tag_double_clicked)
            self._make_tree_compact(self.ui.tw_similar_tags)

        # --- Match details table ---
        self.setup_match_details_widget()

        # --- Inject search bars ---
        self._inject_search_bars()

    def setup_match_details_widget(self):
        """Setup the YARA match details table widget in tabWidget_4."""
        self.tw_yara_match_details = self.ui.tw_yara_match_details

        headers = ['File', 'Rule', 'Pattern ID', 'Offset', 'Data Preview', 'Hex Dump', 'Tag']
        self.tw_yara_match_details.setColumnCount(len(headers))
        self.tw_yara_match_details.setHorizontalHeaderLabels(headers)

        self.tw_yara_match_details.setAlternatingRowColors(True)
        self.tw_yara_match_details.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tw_yara_match_details.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tw_yara_match_details.setSortingEnabled(True)

        header = self.tw_yara_match_details.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)

        self.tw_yara_match_details.setColumnWidth(0, 200)
        self.tw_yara_match_details.setColumnWidth(1, 150)
        self.tw_yara_match_details.setColumnWidth(2, 100)
        self.tw_yara_match_details.setColumnWidth(3, 100)
        self.tw_yara_match_details.setColumnWidth(4, 250)
        self.tw_yara_match_details.setColumnWidth(5, 200)
        self.tw_yara_match_details.setColumnWidth(6, 100)

        self._make_table_compact(self.tw_yara_match_details)
        self.tw_yara_match_details.cellDoubleClicked.connect(self.on_match_detail_double_clicked)

        # Context menu for "Open in Hex Editor at Offset"
        self.tw_yara_match_details.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tw_yara_match_details.customContextMenuRequested.connect(self._show_match_context_menu)

        all_tab_index = self.ui.tabWidget_4.indexOf(self.ui.tab)
        if all_tab_index >= 0:
            self.ui.tabWidget_4.setTabText(all_tab_index, "Match Details")

    def _inject_search_bars(self):
        """Inject debounced search bars above all 6 result widgets."""
        bar = inject_search_bar(self.ui.horizontalLayout_4, self.ui.tv_file_hits, "Filter hits...")
        if bar:
            bar.debounced_text_changed.connect(self.hits_proxy.set_filter_text)
            self._search_bars['hits'] = bar

        bar = inject_search_bar(self.ui.horizontalLayout_5, self.ui.tv_file_misses, "Filter misses...")
        if bar:
            bar.debounced_text_changed.connect(self.misses_proxy.set_filter_text)
            self._search_bars['misses'] = bar

        bar = inject_search_bar(self.ui.horizontalLayout_7, self.ui.tv_rule_details, "Filter details...")
        if bar:
            bar.debounced_text_changed.connect(self.rule_details_proxy.set_filter_text)
            self._search_bars['rule_details'] = bar

        bar = inject_search_bar(self.ui.horizontalLayout_8, self.ui.tw_similar_files, "Filter files...")
        if bar:
            bar.debounced_text_changed.connect(
                lambda text: filter_tree_widget(self.ui.tw_similar_files, text))
            self._search_bars['similar_files'] = bar

        if hasattr(self.ui, 'tw_similar_tags'):
            bar = inject_search_bar(self.ui.horizontalLayout_2, self.ui.tw_similar_tags, "Filter tags...")
            if bar:
                bar.debounced_text_changed.connect(
                    lambda text: filter_tree_widget(self.ui.tw_similar_tags, text))
                self._search_bars['similar_tags'] = bar

        bar = inject_search_bar(self.ui.horizontalLayout_6, self.ui.tw_yara_match_details, "Filter matches...")
        if bar:
            bar.debounced_text_changed.connect(
                lambda text: filter_table_widget(self.tw_yara_match_details, text))
            self._search_bars['match_details'] = bar

    # ─── Table/Tree utility helpers ──────────────────────────────────────

    def _make_table_compact(self, table_view):
        """Make table rows thin and compact."""
        table_view.verticalHeader().setDefaultSectionSize(18)
        table_view.verticalHeader().setMinimumSectionSize(16)
        table_view.verticalHeader().setMaximumSectionSize(20)
        table_view.verticalHeader().setVisible(False)
        table_view.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)

    def _make_tree_compact(self, tree_widget):
        """Make tree widget compact with thin items."""
        tree_widget.setUniformRowHeights(True)
        tree_widget.header().setDefaultSectionSize(100)
        tree_widget.header().setMinimumSectionSize(50)
        font = tree_widget.font()
        font.setPointSize(max(8, font.pointSize() - 1))
        tree_widget.setFont(font)
        tree_widget.setIndentation(15)

    def _apply_column_color(self, item, col_idx):
        """Apply column-specific background colors to table items."""
        theme = self.theme_manager.current_theme
        if not hasattr(theme.colors, 'column_file'):
            return

        colors = theme.colors
        column_colors = [
            colors.column_file,
            colors.column_rule,
            colors.column_pattern,
            colors.column_offset,
            colors.column_data,
            colors.column_hex,
            colors.table_background
        ]

        if col_idx < len(column_colors):
            item.setBackground(QColor(column_colors[col_idx]))

    def _force_thin_rows(self, table_view):
        """Force all existing rows to be thin."""
        if not table_view.model():
            return
        for row in range(table_view.model().rowCount()):
            table_view.setRowHeight(row, 20)

    # ─── Clear helpers ───────────────────────────────────────────────────

    def clear_rule_details(self):
        self.rule_details_model.clear()
        self.rule_details_model.setHorizontalHeaderLabels(['Property', 'Value'])

    def clear_similar_files(self):
        self.ui.tw_similar_files.clear()
        self.ui.tw_similar_files.setHeaderLabels(['File/Rule', 'Info'])

    def clear_match_details(self):
        self.tw_yara_match_details.setRowCount(0)

    def clear_all(self):
        """Clear all results views (used by Reset)."""
        self.hits_model.clear()
        self.hits_model.setHorizontalHeaderLabels(['File', 'Path'])
        self.misses_model.clear()
        self.misses_model.setHorizontalHeaderLabels(['File', 'Path'])
        self.clear_rule_details()
        self.clear_similar_files()
        self.clear_match_details()
        if hasattr(self.ui, 'tw_similar_tags'):
            self.ui.tw_similar_tags.clear()
            self.ui.tw_similar_tags.setHeaderLabels(['Tag/File', 'Details'])
        self.misses_loaded = False
        for bar in self._search_bars.values():
            bar.clear_filter()

    # ─── Detail row helper ───────────────────────────────────────────────

    def add_detail_row(self, property_name, value):
        """Add a row to rule details."""
        property_item = QStandardItem(property_name)
        value_str = str(value)
        value_item = QStandardItem(value_str)
        property_item.setToolTip(property_name)
        value_item.setToolTip(value_str)
        value_item.setData(value_str, Qt.ItemDataRole.DisplayRole)
        self.rule_details_model.appendRow([property_item, value_item])
        self.ui.tv_rule_details.horizontalHeader().setStretchLastSection(True)

    # ─── Unified populate methods (deduplicated) ─────────────────────────

    def populate_rule_details(self, selected_hits: List[Dict]):
        """Populate rule details for one or more selected files."""
        self.rule_details_model.clear()
        self.rule_details_model.setHorizontalHeaderLabels(['Property', 'Value'])

        if not selected_hits:
            return

        total_rules = len(set(rule['identifier'] for hit in selected_hits for rule in hit['matched_rules']))
        total_matches = sum(len(hit['matched_rules']) for hit in selected_hits)

        self.add_detail_row('\U0001f50d Total Matches', str(total_matches))
        self.add_detail_row('\U0001f3af Unique Rules', str(total_rules))
        self.add_detail_row('\u2500' * 20, '\u2500' * 30)

        for i, hit_data in enumerate(selected_hits):
            filename = hit_data['filename']
            rules_count = len(hit_data['matched_rules'])
            matched_rule_names = [rule['identifier'] for rule in hit_data['matched_rules']]

            self.add_detail_row(f'\U0001f4c4 File {i+1}', filename)
            self.add_detail_row(f'  \U0001f4cd Path', hit_data['filepath'])
            self.add_detail_row(f'  \U0001f3af Rules', f'{rules_count} matches: {", ".join(matched_rule_names)}')
            self.add_detail_row(f'  \U0001f511 MD5', hit_data['md5'])
            self.add_detail_row(f'  \U0001f511 SHA1', hit_data['sha1'])
            self.add_detail_row(f'  \U0001f511 SHA256', hit_data['sha256'])

            if i < len(selected_hits) - 1:
                self.add_detail_row('', '')

        self._force_thin_rows(self.ui.tv_rule_details)

        header = self.ui.tv_rule_details.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.ui.tv_rule_details.setColumnWidth(0, 120)
        self.ui.tv_rule_details.setWordWrap(True)

    def populate_similar_files(self, scan_hits: List[Dict], selected_filepaths: Optional[Set[str]] = None):
        """
        Populate similar files tree showing files grouped by matching rules.

        Args:
            scan_hits: All scan hit data to search through
            selected_filepaths: If provided, marks these files with stars and filters to their rules.
                               If None, shows all rules from all hits.
        """
        self.ui.tw_similar_files.clear()
        self.ui.tw_similar_files.setHeaderLabels(['File/Rule', 'Info'])

        if not scan_hits:
            return

        # Determine which rules to show
        if selected_filepaths:
            # Only show rules that match the selected files
            target_rules = set()
            for hit in scan_hits:
                if hit['filepath'] in selected_filepaths:
                    for rule_match in hit['matched_rules']:
                        target_rules.add(rule_match['identifier'])
        else:
            # Show all rules
            target_rules = set()
            for hit in scan_hits:
                for rule_match in hit['matched_rules']:
                    target_rules.add(rule_match['identifier'])

        # Build rule -> files mapping from ALL scan hits
        rules_to_files: Dict[str, list] = {}
        for rule_name in target_rules:
            rules_to_files[rule_name] = []
            for hit_data in scan_hits:
                hit_rules = {rule['identifier'] for rule in hit_data['matched_rules']}
                if rule_name in hit_rules:
                    is_selected = bool(selected_filepaths and hit_data['filepath'] in selected_filepaths)
                    rules_to_files[rule_name].append({
                        'filename': hit_data['filename'],
                        'filepath': hit_data['filepath'],
                        'is_selected': is_selected
                    })

        # Create tree items sorted by file count (most matches first)
        for rule_name in sorted(rules_to_files.keys(), key=lambda r: len(rules_to_files[r]), reverse=True):
            file_entries = rules_to_files[rule_name]
            total_files = len(file_entries)
            selected_count = sum(1 for f in file_entries if f['is_selected'])

            if total_files == 1:
                rule_display = f"\U0001f3af {rule_name}"
            elif total_files <= 5:
                rule_display = f"\U0001f525 {rule_name}"
            else:
                rule_display = f"\U0001f6a8 {rule_name}"

            rule_info = f"{total_files} files"
            if selected_count > 0:
                rule_info += f" ({selected_count} selected)"

            rule_item = QTreeWidgetItem([rule_display, rule_info])
            rule_item.setToolTip(0, f"Rule: {rule_name}")
            rule_item.setToolTip(1, f"{total_files} total files matched this rule, {selected_count} currently selected")

            file_entries_sorted = sorted(file_entries, key=lambda f: (not f['is_selected'], f['filename']))

            for file_entry in file_entries_sorted:
                filename = file_entry['filename']
                filepath = file_entry['filepath']
                is_selected = file_entry['is_selected']

                # Disambiguate same-named files
                same_name_count = sum(1 for fe in file_entries if fe['filename'] == filename)
                if same_name_count > 1:
                    path_parts = filepath.replace('\\', '/').split('/')
                    if len(path_parts) >= 3:
                        distinguishing_path = f".../{path_parts[-3]}/{path_parts[-2]}"
                    elif len(path_parts) >= 2:
                        distinguishing_path = f".../{path_parts[-2]}"
                    else:
                        distinguishing_path = "root"
                    display_name = f'{filename} [{distinguishing_path}]'
                else:
                    display_name = filename

                if is_selected:
                    display_name += " \u2b50"

                file_item = QTreeWidgetItem([f"  \U0001f4c4 {display_name}", ""])
                file_item.setData(0, 32, filepath)  # Qt.UserRole = 32

                tooltip = f"File: {filename}\nPath: {filepath}"
                if is_selected:
                    tooltip += "\n\u2b50 Currently selected"
                file_item.setToolTip(0, tooltip)

                rule_item.addChild(file_item)

            self.ui.tw_similar_files.addTopLevelItem(rule_item)
            rule_item.setExpanded(True)

        self.ui.tw_similar_files.resizeColumnToContents(0)
        self.ui.tw_similar_files.resizeColumnToContents(1)

        # Re-apply filter if search bar has text
        bar = self._search_bars.get('similar_files')
        if bar and bar.text():
            filter_tree_widget(self.ui.tw_similar_files, bar.text())

    def populate_similar_tags(self, scan_hits: List[Dict], selected_filepaths: Optional[Set[str]] = None):
        """
        Populate similar tags view.

        Args:
            scan_hits: All scan hit data to search through
            selected_filepaths: If provided, only shows tags from these files and marks them.
                               If None, shows tags from all hits.
        """
        if not hasattr(self.ui, 'tw_similar_tags'):
            return

        self.ui.tw_similar_tags.clear()

        if not scan_hits:
            return

        # Collect target tags
        target_tags = set()
        for hit_data in scan_hits:
            if selected_filepaths and hit_data.get('filepath', '') not in selected_filepaths:
                continue
            for rule_info in hit_data.get('matched_rules', []):
                for tag in rule_info.get('tags', []):
                    if tag and tag.strip():
                        target_tags.add(tag.strip())

        if not target_tags:
            no_tags_item = QTreeWidgetItem(["No tags found", ""])
            self.ui.tw_similar_tags.addTopLevelItem(no_tags_item)
            return

        # For each tag, find all files with that tag
        for tag in sorted(target_tags):
            files_with_this_tag = []

            for hit_data in scan_hits:
                filename = hit_data.get('filename', 'Unknown')
                filepath = hit_data.get('filepath', '')

                for rule_info in hit_data.get('matched_rules', []):
                    rule_name = rule_info.get('identifier', 'Unknown')
                    tags = rule_info.get('tags', [])

                    if any(t.strip() == tag for t in tags if t and t.strip()):
                        if not any(f['filepath'] == filepath and f['rule_name'] == rule_name for f in files_with_this_tag):
                            is_selected = bool(selected_filepaths and filepath in selected_filepaths)
                            files_with_this_tag.append({
                                'filename': filename,
                                'filepath': filepath,
                                'rule_name': rule_name,
                                'is_selected': is_selected
                            })

            if files_with_this_tag:
                selected_count = len([f for f in files_with_this_tag if f['is_selected']])
                other_count = len(files_with_this_tag) - selected_count

                tag_display = f"\U0001f3f7\ufe0f {tag}"
                if selected_count > 0 and other_count > 0:
                    tag_info = f"{selected_count} selected + {other_count} others"
                elif selected_count > 0:
                    tag_info = f"{selected_count} selected files only"
                else:
                    tag_info = f"{other_count} files"

                tag_item = QTreeWidgetItem([tag_display, tag_info])
                tag_item.setToolTip(0, f"Tag: {tag}")
                tag_item.setToolTip(1, f"Found in {len(files_with_this_tag)} files total")

                files_sorted = sorted(files_with_this_tag, key=lambda f: (not f['is_selected'], f['filename']))
                for file_info in files_sorted:
                    if file_info['is_selected']:
                        file_display = f"\U0001f4c4 {file_info['filename']} \u2b50"
                        file_info_text = f"Rule: {file_info['rule_name']} (Selected)"
                    else:
                        file_display = f"\U0001f4c4 {file_info['filename']}"
                        file_info_text = f"Rule: {file_info['rule_name']}"

                    file_item = QTreeWidgetItem([file_display, file_info_text])
                    file_item.setToolTip(0, f"File: {file_info['filename']}\nPath: {file_info['filepath']}")
                    file_item.setToolTip(1, f"Rule: {file_info['rule_name']}")
                    tag_item.addChild(file_item)

                self.ui.tw_similar_tags.addTopLevelItem(tag_item)
                tag_item.setExpanded(True)

        self.ui.tw_similar_tags.resizeColumnToContents(0)
        self.ui.tw_similar_tags.resizeColumnToContents(1)

        # Re-apply filter if search bar has text
        bar = self._search_bars.get('similar_tags')
        if bar and bar.text():
            filter_tree_widget(self.ui.tw_similar_tags, bar.text())

    def populate_match_details(self, selected_hits: List[Dict]):
        """Populate match details table for one or more selected files."""
        self.tw_yara_match_details.setRowCount(0)

        if not selected_hits:
            return

        row_count = 0

        for hit_data in selected_hits:
            filename = hit_data['filename']

            for rule_match in hit_data['matched_rules']:
                rule_name = rule_match['identifier']

                for pattern_info in rule_match.get('patterns', []):
                    pattern_name = pattern_info['identifier']
                    for match in pattern_info['matches']:
                        self.tw_yara_match_details.insertRow(row_count)

                        self.tw_yara_match_details.setItem(row_count, 0, QTableWidgetItem(filename))
                        self.tw_yara_match_details.setItem(row_count, 1, QTableWidgetItem(rule_name))
                        self.tw_yara_match_details.setItem(row_count, 2, QTableWidgetItem(pattern_name))
                        offset_widget = QTableWidgetItem(f"0x{match['offset']:08x}")
                        offset_widget.setData(Qt.ItemDataRole.UserRole, match['length'])
                        self.tw_yara_match_details.setItem(row_count, 3, offset_widget)

                        file_data = hit_data.get('file_data', b'')
                        offset = match['offset']
                        length = match['length']

                        if pattern_name in ['No string matches', 'Condition-based match'] or (offset == 0 and length == 0):
                            data_preview = "Rule matched (no string patterns)"
                            hex_dump = "N/A - Condition-based match"
                        else:
                            preview = self._get_data_preview(offset, length, file_data=file_data)
                            if preview:
                                data_preview = preview['text']
                                hex_dump = preview['hex']
                            else:
                                data_preview = f"<offset out of range> ({length} bytes)"
                                hex_dump = f"Offset: 0x{offset:08x}, Length: {length}"

                        self.tw_yara_match_details.setItem(row_count, 4, QTableWidgetItem(data_preview))
                        self.tw_yara_match_details.setItem(row_count, 5, QTableWidgetItem(hex_dump))

                        tags = rule_match.get('tags', [])
                        tag_text = ', '.join(tags) if tags else ''
                        self.tw_yara_match_details.setItem(row_count, 6, QTableWidgetItem(tag_text))

                        for col in range(7):
                            item = self.tw_yara_match_details.item(row_count, col)
                            if item:
                                self._apply_column_color(item, col)

                        row_count += 1

        self._force_thin_rows(self.tw_yara_match_details)

        # Re-apply filter if search bar has text
        bar = self._search_bars.get('match_details')
        if bar and bar.text():
            filter_table_widget(self.tw_yara_match_details, bar.text())

    def populate_misses_tab(self, scan_misses: List[Dict]):
        """Populate the misses tab with files that had no matches."""
        if self.misses_loaded:
            return

        self.misses_model.clear()
        self.misses_model.setHorizontalHeaderLabels(['File', 'Path'])

        for miss_data in scan_misses:
            filename_display = f"\U0001f921 {miss_data['filename']}"
            filename_item = QStandardItem(filename_display)
            filename_item.setToolTip(f"File: {miss_data['filename']}\nStatus: Clean (no threats)")

            filepath = miss_data['filepath']
            if len(filepath) > 50:
                path_display = f"...{filepath[-47:]}"
            else:
                path_display = filepath
            filepath_item = QStandardItem(path_display)
            filepath_item.setToolTip(filepath)
            filepath_item.setData(filepath, Qt.ItemDataRole.UserRole)

            self.misses_model.appendRow([filename_item, filepath_item])

        header = self.ui.tv_file_misses.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self._force_thin_rows(self.ui.tv_file_misses)
        self.misses_loaded = True

    def initialize_similar_tags_widget(self):
        """Initialize similar tags widget with instruction message."""
        if not hasattr(self.ui, 'tw_similar_tags'):
            return
        self.ui.tw_similar_tags.clear()
        instruction_item = QTreeWidgetItem(["Select a file to see similar tags", ""])
        instruction_item.setToolTip(0, "Click on a file in the hits table to see files with similar tags")
        self.ui.tw_similar_tags.addTopLevelItem(instruction_item)

    # ─── Data preview ────────────────────────────────────────────────────

    def _get_data_preview(self, offset: int, length: int,
                          file_data: Optional[bytes] = None,
                          filepath: Optional[str] = None) -> Optional[dict]:
        """
        Get a preview of data at the specified offset.

        Args:
            offset: Byte offset into the data
            length: Number of bytes to read
            file_data: In-memory file content (preferred)
            filepath: Path to file on disk (fallback if file_data is None)

        Returns:
            dict with 'raw', 'text', 'hex' keys, or None
        """
        try:
            if file_data is not None:
                if offset < 0 or offset >= len(file_data):
                    return None
                end_offset = min(offset + length, len(file_data))
                data = file_data[offset:end_offset]
            elif filepath:
                with open(filepath, 'rb') as f:
                    f.seek(offset)
                    data = f.read(length)
            else:
                return None

            if not data:
                return None

            text_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
            hex_dump = ' '.join(f'{b:02X}' for b in data)

            return {
                'raw': data,
                'text': text_preview,
                'hex': hex_dump
            }
        except Exception:
            return None

    # ─── Selection / navigation helpers ──────────────────────────────────

    def select_file(self, filepath: str, scan_hits: List[Dict]):
        """
        Select a file in the hits table by filepath match.
        Maps source row through proxy before selecting.
        """
        for row, hit_data in enumerate(scan_hits):
            if hit_data['filepath'] == filepath:
                source_index = self.hits_model.index(row, 0)
                proxy_index = self.hits_proxy.mapFromSource(source_index)
                if proxy_index.isValid():
                    self.ui.tv_file_hits.selectRow(proxy_index.row())
                return True
        return False

    # ─── Double-click handlers ───────────────────────────────────────────

    def on_match_detail_double_clicked(self, row, column):
        """Handle double-click of a match detail row."""
        if row < 0:
            return

        filename_item = self.tw_yara_match_details.item(row, 0)
        rule_item = self.tw_yara_match_details.item(row, 1)
        pattern_item = self.tw_yara_match_details.item(row, 2)
        offset_item = self.tw_yara_match_details.item(row, 3)

        if not all([filename_item, rule_item, pattern_item, offset_item]):
            return

        filename = filename_item.text()
        rule_name = rule_item.text()
        pattern_id = pattern_item.text()
        offset_hex = offset_item.text()

        try:
            offset = int(offset_hex, 16) if offset_hex.startswith('0x') else int(offset_hex)
            msg = f"Selected: {filename} | Rule: {rule_name} | Pattern: {pattern_id} | Offset: {offset_hex} ({offset:,} dec)"
            self.status_message_requested.emit(msg, 10000)
        except ValueError:
            msg = f"Selected: {filename} | Rule: {rule_name} | Pattern: {pattern_id}"
            self.status_message_requested.emit(msg, 5000)

        # Request MainWindow to select this file
        self.file_selection_requested.emit(filename)

    def _show_match_context_menu(self, pos):
        """Show context menu on match details for hex editor navigation."""
        row = self.tw_yara_match_details.rowAt(pos.y())
        if row < 0:
            return

        filename_item = self.tw_yara_match_details.item(row, 0)
        offset_item = self.tw_yara_match_details.item(row, 3)
        if not filename_item or not offset_item:
            return

        menu = QMenu(self.tw_yara_match_details)
        hex_action = menu.addAction("Open in Hex Editor at Offset")
        action = menu.exec(self.tw_yara_match_details.viewport().mapToGlobal(pos))
        if action == hex_action:
            filename = filename_item.text()
            offset_hex = offset_item.text()
            try:
                offset = int(offset_hex, 16) if offset_hex.startswith("0x") else int(offset_hex)
            except ValueError:
                offset = 0

            match_length = offset_item.data(Qt.ItemDataRole.UserRole)
            if not match_length or not isinstance(match_length, int):
                match_length = 0

            self.hex_editor_requested.emit(filename, offset, match_length)

    def _show_misses_context_menu(self, pos):
        """Show context menu on misses table for hex editor."""
        index = self.ui.tv_file_misses.indexAt(pos)
        if not index.isValid():
            return

        source_index = self.misses_proxy.mapToSource(index)
        row = source_index.row()
        filepath_item = self.misses_model.item(row, 1)
        if not filepath_item:
            return

        filepath = filepath_item.data(Qt.ItemDataRole.UserRole)
        if not filepath:
            filepath = filepath_item.toolTip()  # fallback
        if not filepath:
            return

        menu = QMenu(self.ui.tv_file_misses)
        hex_action = menu.addAction("Open in Hex Editor")
        action = menu.exec(self.ui.tv_file_misses.viewport().mapToGlobal(pos))
        if action == hex_action:
            self.hex_editor_requested.emit(filepath, 0, 0)

    def on_similar_file_double_clicked(self, item, column):
        """Handle double-click of a similar file to synchronize with hits list."""
        if not item:
            return

        try:
            filepath = item.data(0, 32)  # Qt.UserRole = 32
            item_text = item.text(0)
            has_parent = item.parent() is not None
        except RuntimeError:
            return

        if filepath:
            self.file_selection_requested.emit(filepath)
        else:
            filename = None
            if item_text.startswith('\U0001f4c4 '):
                filename = item_text[2:].split(' (')[0]
                filename = filename.replace(' \u2b50', '').strip()
            elif item_text.startswith('File: '):
                filename = item_text[6:]
            elif not has_parent:
                if not any(keyword in item_text.lower() for keyword in ['rule', 'condition', 'strings', 'meta']):
                    filename = item_text

            if filename:
                self.file_selection_requested.emit(filename)

    def on_similar_tag_double_clicked(self, item, column):
        """Handle double-click of a similar tag item."""
        if not item:
            return

        try:
            item_text = item.text(0)
            parent_item = item.parent()
            parent_text = parent_item.text(0) if parent_item else None
            child_count = item.childCount()
            first_child = item.child(0) if child_count > 0 else None
        except RuntimeError:
            return

        filename = None
        tag_name = None

        if item_text.startswith('\U0001f4c4 '):
            filename = item_text[2:]
            filename = filename.replace(' \u2b50', '').strip()
        elif item_text.startswith('\U0001f3f7\ufe0f '):
            tag_name = item_text[3:]
            if first_child:
                try:
                    first_child_text = first_child.text(0)
                    if first_child_text.startswith('\U0001f4c4 '):
                        filename = first_child_text[2:]
                        filename = filename.replace(' \u2b50', '').strip()
                except RuntimeError:
                    pass

        if filename:
            self.file_selection_requested.emit(filename)

            if tag_name or (parent_text and parent_text.startswith('\U0001f3f7\ufe0f ')):
                parent_tag = tag_name if tag_name else (parent_text[3:] if parent_text else None)
                if parent_tag:
                    self.tag_highlight_requested.emit(parent_tag)
