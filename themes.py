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
    font_family: str = "Cascadia Code"
    font_size: int = 7
    editor_font_family: str = "Cascadia Code"
    editor_font_size: int = 12  # Increased for better readability
    
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
            editor_font_size=data.get('editor_font_size', 12),
            border_radius=data.get('border_radius', 4),
            border_width=data.get('border_width', 1),
            padding_small=data.get('padding_small', 4),
            padding_medium=data.get('padding_medium', 8),
            padding_large=data.get('padding_large', 12),
            animation_duration=data.get('animation_duration', 150)
        )


# All themes are now loaded from themes.json


class ThemeManager:
    """Manages theme loading, saving, and application"""
    
    def __init__(self, config_dir: Path = None):
        if config_dir is None:
            config_dir = Path(__file__).parent / "config"
        
        self.config_dir = config_dir
        self.config_dir.mkdir(exist_ok=True)
        self.themes_file = self.config_dir / "themes.json"
        
        # All themes are now loaded from JSON
        self.all_themes: Dict[str, ThemeSettings] = {}
        self.current_theme: ThemeSettings = None
        
        self.load_all_themes()
    
    def get_available_themes(self) -> Dict[str, ThemeSettings]:
        """Get all available themes from JSON"""
        return self.all_themes.copy()
    
    def get_theme(self, name: str) -> ThemeSettings:
        """Get theme by name"""
        # Return the requested theme or fallback to Light theme
        if name in self.all_themes:
            return self.all_themes[name]
        elif "Light" in self.all_themes:
            return self.all_themes["Light"]
        elif self.all_themes:
            # If Light theme doesn't exist, return the first available theme
            return list(self.all_themes.values())[0]
        else:
            # Create a minimal fallback theme if no themes are loaded
            return self._create_fallback_theme()
    
    def set_current_theme(self, name: str):
        """Set the current active theme"""
        self.current_theme = self.get_theme(name)
    
    def load_all_themes(self):
        """Load all themes from config file"""
        if self.themes_file.exists():
            try:
                with open(self.themes_file, 'r', encoding='utf-8') as f:
                    themes_data = json.load(f)
                
                for name, theme_data in themes_data.items():
                    if not name.startswith('_') and isinstance(theme_data, dict):
                        self.all_themes[name] = ThemeSettings.from_dict(theme_data)
                        
                # Set default theme if current_theme is not set
                if self.current_theme is None:
                    if "Light" in self.all_themes:
                        self.current_theme = self.all_themes["Light"]
                    elif self.all_themes:
                        self.current_theme = list(self.all_themes.values())[0]
                        
            except Exception as e:
                print(f"Error loading themes: {e}")
                self.current_theme = self._create_fallback_theme()
        else:
            print(f"Themes file not found: {self.themes_file}")
            self.current_theme = self._create_fallback_theme()
    
    def save_theme(self, theme: ThemeSettings):
        """Save a theme to the JSON file"""
        self.all_themes[theme.name] = theme
        
        # Save all themes to file
        try:
            themes_data = {name: theme.to_dict() for name, theme in self.all_themes.items()}
            
            with open(self.themes_file, 'w', encoding='utf-8') as f:
                json.dump(themes_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print(f"Error saving themes: {e}")
    
    def _create_fallback_theme(self) -> ThemeSettings:
        """Create a minimal fallback theme when no themes are available"""
        return ThemeSettings(
            name="Fallback Light",
            colors=ThemeColors(
                background="#ffffff", surface="#f0f0f0", primary="#0078d4", secondary="#666666", accent="#ff0000",
                text_primary="#000000", text_secondary="#666666", text_disabled="#cccccc", text_inverse="#ffffff",
                button_normal="#e0e0e0", button_hover="#d0d0d0", button_pressed="#c0c0c0",
                selection_background="#0078d4", selection_text="#ffffff", selection_inactive="#cccccc", hover_background="#f0f0f0",
                editor_background="#ffffff", editor_text="#000000", editor_line_number_bg="#f0f0f0", editor_line_number_text="#666666", 
                editor_current_line="#f8f8f8", editor_selection="#add8e6",
                table_background="#ffffff", table_alternate="#f8f8f8", table_header_bg="#e0e0e0", table_header_text="#000000", table_border="#cccccc",
                success="#008000", warning="#ffa500", error="#ff0000", info="#0000ff",
                splitter_handle="#cccccc", splitter_pressed="#aaaaaa",
                tab_active_bg="#ffffff", tab_active_text="#000000", tab_inactive_bg="#f0f0f0", tab_inactive_text="#666666",
                scrollbar_background="#f0f0f0", scrollbar_handle="#cccccc", scrollbar_handle_hover="#aaaaaa",
                checkbox_background="#ffffff", checkbox_border="#cccccc", checkbox_checked_border="#0078d4", 
                checkbox_checked_mark="#0078d4", checkbox_hover_border="#0078d4", checkbox_indeterminate="#ffa500",
                syntax_keyword="#0000ff", syntax_logic="#800080", syntax_builtin="#008000", syntax_modifier="#ff8000",
                syntax_module="#008080", syntax_symbol="#000080", syntax_number="#008000", syntax_string="#ff0000",
                syntax_regex="#800080", syntax_hex="#ff8000", syntax_comment="#008000", syntax_identifier="#000080",
                syntax_meta_key="#008000", syntax_tag="#ff8000", syntax_condition="#800080", syntax_operator="#000000",
                syntax_literal="#ff0000", syntax_function="#008080", syntax_section="#0000ff",
                column_file="#f0f8ff", column_rule="#f0fff0", column_pattern="#fff8dc", column_offset="#ffe4e1", 
                column_data="#f5f5dc", column_hex="#e6e6fa"
            )
        )
    
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
            selection-color: {colors.editor_text};
        }}
        
        QTextEdit::selection, QPlainTextEdit::selection {{
            background-color: {colors.editor_selection};
            color: {colors.editor_text};
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