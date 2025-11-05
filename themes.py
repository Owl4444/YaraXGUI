# -*- coding: utf-8 -*-
"""
Theme configuration system for YaraXGUI
Provides light and dark themes with easy customization
"""

from dataclasses import dataclass
from typing import Dict, Any
import json
from pathlib import Path


@dataclass
class ThemeColors:
    """Theme color definitions"""
    # Base colors
    background: str
    surface: str
    primary: str
    secondary: str
    accent: str
    
    # Text colors
    text_primary: str
    text_secondary: str
    text_disabled: str
    text_inverse: str
    
    # Interactive colors
    button_normal: str
    button_hover: str
    button_pressed: str
    
    # Selection and highlighting
    selection_background: str
    selection_text: str
    selection_inactive: str
    hover_background: str
    
    # Editor colors
    editor_background: str
    editor_text: str
    editor_line_number_bg: str
    editor_line_number_text: str
    editor_current_line: str
    editor_selection: str
    
    # Table/Tree colors
    table_background: str
    table_alternate: str
    table_header_bg: str
    table_header_text: str
    table_border: str
    
    # Status colors
    success: str
    warning: str
    error: str
    info: str
    
    # Splitter colors
    splitter_handle: str
    splitter_pressed: str
    
    # Tab colors
    tab_active_bg: str
    tab_active_text: str
    tab_inactive_bg: str
    tab_inactive_text: str
    
    # Scrollbar colors
    scrollbar_background: str
    scrollbar_handle: str
    scrollbar_handle_hover: str
    
    # Checkbox colors
    checkbox_background: str
    checkbox_border: str
    checkbox_checked_border: str
    checkbox_checked_mark: str
    checkbox_hover_border: str
    checkbox_indeterminate: str
    
    # Syntax highlighting colors
    syntax_keyword: str          # rule, strings, condition, etc.
    syntax_logic: str           # and, or, not, any, all
    syntax_builtin: str         # filesize, uint32, entrypoint
    syntax_modifier: str        # ascii, wide, nocase
    syntax_module: str          # pe, elf, dotnet (before .)
    syntax_symbol: str          # $a, #a, @a[i]
    syntax_number: str          # 0xFF, 1234
    syntax_string: str          # "string literals"
    syntax_regex: str           # /regex/i
    syntax_hex: str             # { 6A 40 ?? }
    syntax_comment: str         # // and /* */
    
    # Enhanced AST-based syntax colors (with defaults for backward compatibility)
    syntax_identifier: str = "#FFA366"      # Rule names, identifiers
    syntax_meta_key: str = "#4ec9b0"        # Meta keys (author, description)  
    syntax_tag: str = "#dcdcaa"             # Rule tags
    syntax_condition: str = "#c586c0"       # Condition keywords
    syntax_operator: str = "#d4d4d4"        # Operators (==, !=, +, -, etc.)
    syntax_literal: str = "#ce9178"         # String/hex literals
    syntax_function: str = "#4fc1ff"        # Function calls
    syntax_section: str = "#569cd6"         # Section keywords (meta:, strings:, condition:)
    
    # Table column colors for match details (with defaults for backward compatibility)
    column_file: str = "#f8fcff"            # File column background
    column_rule: str = "#f8fff8"            # Rule column background  
    column_pattern: str = "#fffdf8"         # Pattern ID column background
    column_offset: str = "#fff8f8"          # Offset column background
    column_data: str = "#f9fff8"            # Data Preview column background
    column_hex: str = "#f9f8ff"             # Hex Dump column background


@dataclass
class ThemeSettings:
    """Complete theme settings including colors and other properties"""
    name: str
    colors: ThemeColors
    
    # Font settings
    font_family: str = "Segoe UI"
    font_size: int = 9
    editor_font_family: str = "Consolas"
    editor_font_size: int = 10
    
    # UI settings
    border_radius: int = 4
    border_width: int = 1
    padding_small: int = 4
    padding_medium: int = 8
    padding_large: int = 12
    
    # Animation settings
    animation_duration: int = 150
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert theme to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'colors': {
                field.name: getattr(self.colors, field.name)
                for field in self.colors.__dataclass_fields__.values()
            },
            'font_family': self.font_family,
            'font_size': self.font_size,
            'editor_font_family': self.editor_font_family,
            'editor_font_size': self.editor_font_size,
            'border_radius': self.border_radius,
            'border_width': self.border_width,
            'padding_small': self.padding_small,
            'padding_medium': self.padding_medium,
            'padding_large': self.padding_large,
            'animation_duration': self.animation_duration
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThemeSettings':
        """Create theme from dictionary"""
        colors_data = data['colors'].copy()
        
        # Provide fallbacks for new syntax highlighting colors if not present
        syntax_fallbacks = {
            'syntax_identifier': colors_data.get('syntax_symbol', '#FFA366'),
            'syntax_meta_key': colors_data.get('syntax_builtin', '#4ec9b0'),
            'syntax_tag': colors_data.get('syntax_modifier', '#dcdcaa'),
            'syntax_condition': colors_data.get('syntax_logic', '#c586c0'),
            'syntax_operator': colors_data.get('syntax_logic', '#d4d4d4'),
            'syntax_literal': colors_data.get('syntax_string', '#ce9178'),
            'syntax_function': colors_data.get('syntax_module', '#4fc1ff'),
            'syntax_section': colors_data.get('syntax_keyword', '#569cd6')
        }
        
        # Provide fallbacks for column colors if not present
        column_fallbacks = {
            'column_file': colors_data.get('table_alternate', '#f8fcff'),
            'column_rule': colors_data.get('table_alternate', '#f8fff8'),
            'column_pattern': colors_data.get('table_alternate', '#fffdf8'),
            'column_offset': colors_data.get('table_alternate', '#fff8f8'),
            'column_data': colors_data.get('table_alternate', '#f9fff8'),
            'column_hex': colors_data.get('table_alternate', '#f9f8ff')
        }
        
        # Add missing colors with fallbacks
        all_fallbacks = {**syntax_fallbacks, **column_fallbacks}
        for key, fallback_value in all_fallbacks.items():
            if key not in colors_data:
                colors_data[key] = fallback_value
        
        colors = ThemeColors(**colors_data)
        return cls(
            name=data['name'],
            colors=colors,
            font_family=data.get('font_family', 'Segoe UI'),
            font_size=data.get('font_size', 9),
            editor_font_family=data.get('editor_font_family', 'Consolas'),
            editor_font_size=data.get('editor_font_size', 10),
            border_radius=data.get('border_radius', 4),
            border_width=data.get('border_width', 1),
            padding_small=data.get('padding_small', 4),
            padding_medium=data.get('padding_medium', 8),
            padding_large=data.get('padding_large', 12),
            animation_duration=data.get('animation_duration', 150)
        )


# Predefined themes
LIGHT_THEME = ThemeSettings(
    name="Light",
    colors=ThemeColors(
        # Base colors
        background="#ffffff",
        surface="#f8f9fa",
        primary="#0078d4",
        secondary="#6c757d",
        accent="#dc3545",
        
        # Text colors
        text_primary="#212529",
        text_secondary="#6c757d",
        text_disabled="#adb5bd",
        text_inverse="#ffffff",
        
        # Interactive colors
        button_normal="#e9ecef",
        button_hover="#dee2e6",
        button_pressed="#ced4da",
        
        # Selection and highlighting
        selection_background="#dc3545",
        selection_text="#ffffff",
        selection_inactive="#dc3545",
        hover_background="#e9ecef",
        
        # Editor colors
        editor_background="#ffffff",
        editor_text="#212529",
        editor_line_number_bg="#f8f9fa",
        editor_line_number_text="#6c757d",
        editor_current_line="#fafbfc",
        editor_selection="#e3f2fd",
        
        # Table/Tree colors
        table_background="#ffffff",
        table_alternate="#f8f9fa",
        table_header_bg="#e9ecef",
        table_header_text="#495057",
        table_border="#dee2e6",
        
        # Status colors
        success="#28a745",
        warning="#ffc107",
        error="#dc3545",
        info="#17a2b8",
        
        # Splitter colors
        splitter_handle="#dee2e6",
        splitter_pressed="#ced4da",
        
        # Tab colors
        tab_active_bg="#ffffff",
        tab_active_text="#495057",
        tab_inactive_bg="#e9ecef",
        tab_inactive_text="#6c757d",
        
        # Scrollbar colors
        scrollbar_background="#f1f3f4",
        scrollbar_handle="#ced4da",
        scrollbar_handle_hover="#adb5bd",
        
        # Checkbox colors
        checkbox_background="#ffffff",
        checkbox_border="#dee2e6",
        checkbox_checked_border="#dc3545",
        checkbox_checked_mark="#dc3545",
        checkbox_hover_border="#0078d4",
        checkbox_indeterminate="#ffc107",
        
        # Syntax highlighting colors (optimized for light backgrounds)
        syntax_keyword="#0066cc",      # Blue - keywords like 'rule', 'condition'
        syntax_logic="#9900cc",        # Purple - logic operators 'and', 'or', 'not'
        syntax_builtin="#cc6600",      # Orange-brown - built-ins like 'filesize'
        syntax_modifier="#996633",     # Brown - string modifiers 'ascii', 'wide'
        syntax_module="#006666",       # Teal - modules 'pe', 'elf'
        syntax_symbol="#0066aa",       # Dark blue - symbols $a, #a, @a
        syntax_number="#009900",       # Green - numbers and hex values
        syntax_string="#cc0000",       # Red - string literals
        syntax_regex="#990066",        # Dark pink - regex patterns
        syntax_hex="#cc9900",          # Gold - hex strings { 6A 40 }
        syntax_comment="#669900",      # Olive green - comments
        
        # Table column colors for better readability (light theme)
        column_file="#f0f8ff",         # Alice blue - file names
        column_rule="#f0fff0",         # Honeydew - rule names  
        column_pattern="#fff8dc",      # Cornsilk - pattern IDs
        column_offset="#ffe4e1",       # Misty rose - offsets
        column_data="#f5f5dc",         # Beige - data preview
        column_hex="#e6e6fa"           # Lavender - hex dump
    )
)

DARK_THEME = ThemeSettings(
    name="Dark",
    colors=ThemeColors(
        # Base colors
        background="#1e1e1e",
        surface="#252526",
        primary="#0e639c",
        secondary="#858585",
        accent="#f14c4c",
        
        # Text colors
        text_primary="#cccccc",
        text_secondary="#858585",
        text_disabled="#5a5a5a",
        text_inverse="#1e1e1e",
        
        # Interactive colors
        button_normal="#2d2d30",
        button_hover="#3e3e42",
        button_pressed="#464647",
        
        # Selection and highlighting
        selection_background="#f14c4c",
        selection_text="#ffffff",
        selection_inactive="#f14c4c",
        hover_background="#2a2d2e",
        
        # Editor colors
        editor_background="#1e1e1e",
        editor_text="#d4d4d4",
        editor_line_number_bg="#252526",
        editor_line_number_text="#858585",
        editor_current_line="#2a2d2e",
        editor_selection="#264f78",
        
        # Table/Tree colors
        table_background="#1e1e1e",
        table_alternate="#252526",
        table_header_bg="#2d2d30",
        table_header_text="#cccccc",
        table_border="#3e3e42",
        
        # Status colors
        success="#4ec9b0",
        warning="#ffcc02",
        error="#f14c4c",
        info="#9cdcfe",
        
        # Splitter colors
        splitter_handle="#3e3e42",
        splitter_pressed="#464647",
        
        # Tab colors
        tab_active_bg="#1e1e1e",
        tab_active_text="#cccccc",
        tab_inactive_bg="#2d2d30",
        tab_inactive_text="#858585",
        
        # Scrollbar colors
        scrollbar_background="#2e2e2e",
        scrollbar_handle="#424242",
        scrollbar_handle_hover="#4e4e4e",
        
        # Checkbox colors
        checkbox_background="#1e1e1e",
        checkbox_border="#3e3e42",
        checkbox_checked_border="#f14c4c",
        checkbox_checked_mark="#f14c4c",
        checkbox_hover_border="#0e639c",
        checkbox_indeterminate="#ffcc02",
        
        # Syntax highlighting colors (optimized for dark backgrounds)
        syntax_keyword="#5ba7f7",      # Light blue - keywords like 'rule', 'condition'
        syntax_logic="#d19ce6",        # Light purple - logic operators 'and', 'or', 'not'
        syntax_builtin="#4dd0e1",      # Cyan - built-ins like 'filesize', 'uint32'
        syntax_modifier="#fff176",     # Light yellow - string modifiers 'ascii', 'wide'
        syntax_module="#81c784",       # Light green - modules 'pe', 'elf'
        syntax_symbol="#90caf9",       # Pale blue - symbols $a, #a, @a
        syntax_number="#a5d6a7",       # Mint green - numbers and hex values
        syntax_string="#ffab91",       # Peach - string literals (much better than red!)
        syntax_regex="#f8bbd9",        # Pink - regex patterns
        syntax_hex="#ffe082",          # Light gold - hex strings { 6A 40 }
        syntax_comment="#81c784",      # Light green - comments
        
        # Table column colors for better readability (dark theme)
        column_file="#2a2d3e",         # Dark blue-gray - file names
        column_rule="#2d2a3e",         # Dark purple-gray - rule names
        column_pattern="#3e2d2a",      # Dark brown-gray - pattern IDs
        column_offset="#3e2a2d",       # Dark red-gray - offsets
        column_data="#2d3e2a",         # Dark green-gray - data preview
        column_hex="#2a3e2d"           # Dark teal-gray - hex dump
    )
)


class ThemeManager:
    """Manages theme loading, saving, and application"""
    
    def __init__(self, config_dir: Path = None):
        if config_dir is None:
            config_dir = Path(__file__).parent / "config"
        
        self.config_dir = config_dir
        self.config_dir.mkdir(exist_ok=True)
        self.themes_file = self.config_dir / "themes.json"
        
        # Built-in themes
        self.built_in_themes = {
            "Light": LIGHT_THEME,
            "Dark": DARK_THEME
        }
        
        self.custom_themes: Dict[str, ThemeSettings] = {}
        self.current_theme: ThemeSettings = LIGHT_THEME
        
        self.load_custom_themes()
    
    def get_available_themes(self) -> Dict[str, ThemeSettings]:
        """Get all available themes (built-in + custom)"""
        all_themes = self.built_in_themes.copy()
        all_themes.update(self.custom_themes)
        return all_themes
    
    def get_theme(self, name: str) -> ThemeSettings:
        """Get theme by name"""
        all_themes = self.get_available_themes()
        return all_themes.get(name, LIGHT_THEME)
    
    def set_current_theme(self, name: str):
        """Set the current active theme"""
        self.current_theme = self.get_theme(name)
    
    def load_custom_themes(self):
        """Load custom themes from config file"""
        if self.themes_file.exists():
            try:
                with open(self.themes_file, 'r', encoding='utf-8') as f:
                    themes_data = json.load(f)
                
                for name, theme_data in themes_data.items():
                    if name not in self.built_in_themes and not name.startswith('_') and isinstance(theme_data, dict):
                        self.custom_themes[name] = ThemeSettings.from_dict(theme_data)
                        
            except Exception as e:
                print(f"Error loading custom themes: {e}")
    
    def save_custom_theme(self, theme: ThemeSettings):
        """Save a custom theme"""
        self.custom_themes[theme.name] = theme
        
        # Save to file
        try:
            themes_data = {name: theme.to_dict() for name, theme in self.custom_themes.items()}
            
            with open(self.themes_file, 'w', encoding='utf-8') as f:
                json.dump(themes_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print(f"Error saving custom themes: {e}")
    
    def generate_qss_stylesheet(self, theme: ThemeSettings = None) -> str:
        """Generate complete QSS stylesheet from theme"""
        if theme is None:
            theme = self.current_theme
        
        colors = theme.colors
        
        return f"""
        /* Main Application Styling */
        QMainWindow {{
            background-color: {colors.background};
            color: {colors.text_primary};
            font-family: {theme.font_family};
            font-size: {theme.font_size}pt;
        }}
        
        /* Tables and Lists */
        QTableView, QTreeView, QListWidget {{
            background-color: {colors.table_background};
            alternate-background-color: {colors.table_alternate};
            color: {colors.text_primary};
            border: {theme.border_width}px solid {colors.table_border};
            gridline-color: {colors.table_border};
            selection-background-color: {colors.selection_background};
            selection-color: {colors.selection_text};
        }}
        
        QTableView::item:selected, QTreeView::item:selected, QListWidget::item:selected {{
            background-color: {colors.selection_background};
            color: {colors.selection_text};
        }}
        
        QTableView::item:selected:!active, QTreeView::item:selected:!active, QListWidget::item:selected:!active {{
            background-color: {colors.selection_inactive};
            color: {colors.selection_text};
        }}
        
        QTableView::item:hover, QTreeView::item:hover, QListWidget::item:hover {{
            background-color: {colors.hover_background};
        }}
        
        /* Headers */
        QHeaderView::section {{
            background-color: {colors.table_header_bg};
            color: {colors.table_header_text};
            border: {theme.border_width}px solid {colors.table_border};
            padding: 2px {theme.padding_small}px;
            font-size: {max(theme.font_size - 1, 7)}pt;
            font-weight: 600;
        }}
        
        QHeaderView::section:hover {{
            background-color: {colors.button_hover};
        }}
        
        QHeaderView::section:pressed {{
            background-color: {colors.button_pressed};
        }}
        
        /* Buttons */
        QPushButton {{
            background-color: {colors.button_normal};
            color: {colors.text_primary};
            border: {theme.border_width}px solid {colors.table_border};
            border-radius: {theme.border_radius}px;
            padding: {theme.padding_small}px {theme.padding_medium}px;
            font-weight: bold;
        }}
        
        QPushButton:hover {{
            background-color: {colors.button_hover};
        }}
        
        QPushButton:pressed {{
            background-color: {colors.button_pressed};
        }}
        
        QPushButton:disabled {{
            background-color: {colors.surface};
            color: {colors.text_disabled};
        }}
        
        /* Text Editor */
        QTextEdit, QPlainTextEdit {{
            background-color: {colors.editor_background};
            color: {colors.editor_text};
            border: {theme.border_width}px solid {colors.table_border};
            font-family: {theme.editor_font_family};
            font-size: {theme.editor_font_size}pt;
            selection-background-color: {colors.editor_selection};
        }}
        
        /* Text Browser */
        QTextBrowser {{
            background-color: {colors.table_background};
            color: {colors.text_primary};
            border: {theme.border_width}px solid {colors.table_border};
        }}
        
        /* Tabs */
        QTabWidget::pane {{
            border: {theme.border_width}px solid {colors.table_border};
            background-color: {colors.surface};
        }}
        
        QTabWidget::tab-bar {{
            alignment: left;
        }}
        
        QTabBar::tab {{
            background-color: {colors.tab_inactive_bg};
            color: {colors.tab_inactive_text};
            border: {theme.border_width}px solid {colors.table_border};
            padding: {theme.padding_small}px {theme.padding_medium}px;
            margin-right: 2px;
        }}
        
        QTabBar::tab:selected {{
            background-color: {colors.tab_active_bg};
            color: {colors.tab_active_text};
            border-bottom-color: {colors.tab_active_bg};
        }}
        
        QTabBar::tab:hover:!selected {{
            background-color: {colors.hover_background};
        }}
        
        /* Splitter */
        QSplitter::handle {{
            background-color: {colors.splitter_handle};
        }}
        
        QSplitter::handle:pressed {{
            background-color: {colors.splitter_pressed};
        }}
        
        QSplitter::handle:horizontal {{
            width: 3px;
        }}
        
        QSplitter::handle:vertical {{
            height: 3px;
        }}
        
        /* Scrollbars */
        QScrollBar:vertical, QScrollBar:horizontal {{
            background-color: {colors.scrollbar_background};
            border: none;
        }}
        
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
            background-color: {colors.scrollbar_handle};
            border-radius: {theme.border_radius}px;
        }}
        
        QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
            background-color: {colors.scrollbar_handle_hover};
        }}
        
        QScrollBar:vertical {{
            width: 12px;
        }}
        
        QScrollBar:horizontal {{
            height: 12px;
        }}
        
        QScrollBar::add-line, QScrollBar::sub-line {{
            border: none;
            background: none;
        }}
        
        /* Status Bar */
        QStatusBar {{
            background-color: {colors.surface};
            color: {colors.text_secondary};
            border-top: {theme.border_width}px solid {colors.table_border};
        }}
        
        /* Menu Bar */
        QMenuBar {{
            background-color: {colors.surface};
            color: {colors.text_primary};
            border-bottom: {theme.border_width}px solid {colors.table_border};
        }}
        
        QMenuBar::item {{
            background-color: transparent;
            padding: {theme.padding_small}px {theme.padding_medium}px;
        }}
        
        QMenuBar::item:selected {{
            background-color: {colors.hover_background};
        }}
        
        /* Tool Tips */
        QToolTip {{
            background-color: {colors.surface};
            color: {colors.text_primary};
            border: {theme.border_width}px solid {colors.table_border};
            border-radius: {theme.border_radius}px;
            padding: {theme.padding_small}px;
        }}
        
        /* Group Box */
        QGroupBox {{
            color: {colors.text_primary};
            border: {theme.border_width}px solid {colors.table_border};
            border-radius: {theme.border_radius}px;
            margin-top: 1ex;
            padding-top: {theme.padding_medium}px;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: {theme.padding_medium}px;
            padding: 0 {theme.padding_small}px 0 {theme.padding_small}px;
        }}
        
        /* Checkboxes */
        QCheckBox {{
            color: {colors.text_primary};
            spacing: 5px;
        }}
        
        QCheckBox::indicator {{
            width: 16px;
            height: 16px;
            border: {theme.border_width}px solid {colors.table_border};
            border-radius: {theme.border_radius}px;
            background-color: {colors.table_background};
        }}
        
        QCheckBox::indicator:hover {{
            border-color: {colors.primary};
            background-color: {colors.hover_background};
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {colors.primary};
            border-color: {colors.primary};
            border: 2px solid {colors.primary};
        }}
        
        QCheckBox::indicator:checked:hover {{
            background-color: {colors.accent};
            border-color: {colors.accent};
        }}
        
        QCheckBox::indicator:unchecked {{
            background-color: {colors.table_background};
            border-color: {colors.table_border};
        }}
        
        QCheckBox::indicator:disabled {{
            background-color: {colors.surface};
            border-color: {colors.text_disabled};
        }}
        
        /* Tree View Checkboxes (for your directory tree) */
        QTreeView::indicator {{
            width: 18px;
            height: 18px;
            border: 2px solid {colors.checkbox_border};
            border-radius: 3px;
            background-color: {colors.checkbox_background};
        }}
        
        QTreeView::indicator:hover {{
            border: 2px solid {colors.checkbox_hover_border};
            background-color: {colors.hover_background};
        }}
        
        QTreeView::indicator:checked {{
            background-color: {colors.checkbox_checked_border};
            border: 2px solid {colors.checkbox_checked_border};
            border-radius: 3px;
        }}
        
        QTreeView::indicator:checked:hover {{
            background-color: {colors.checkbox_hover_border};
            border: 2px solid {colors.checkbox_hover_border};
        }}
        
        QTreeView::indicator:unchecked {{
            background-color: {colors.checkbox_background};
            border: 2px solid {colors.checkbox_border};
            border-radius: 3px;
        }}
        
        QTreeView::indicator:unchecked:hover {{
            border: 2px solid {colors.checkbox_hover_border};
            background-color: {colors.hover_background};
        }}
        
        QTreeView::indicator:indeterminate {{
            background-color: {colors.checkbox_indeterminate};
            border: 2px solid {colors.checkbox_indeterminate};
            border-radius: 3px;
        }}
        
        QTreeView::indicator:disabled {{
            background-color: {colors.surface};
            border: 2px solid {colors.text_disabled};
            border-radius: 3px;
        }}
        """


# Global theme manager instance
theme_manager = ThemeManager()