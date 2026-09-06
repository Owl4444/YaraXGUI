# YaraXGUI Theming System

The YaraXGUI application now includes a comprehensive theming system that allows you to customize the appearance of the entire application.

## Built-in Themes

The application comes with two built-in themes:

- **Light**: A clean, professional light theme suitable for bright environments
- **Dark**: A modern dark theme that's easy on the eyes for extended use

## Theme Selection

You can switch themes using the theme selector in the bottom-right corner of the status bar. Your theme preference is automatically saved and restored when you restart the application.

## Creating Custom Themes

### Step 1: Start with a Built-in Theme
In a source checkout, back up `config/themes.json`, then duplicate an existing
theme entry under a new name. Keep all its color fields and adjust them as needed.

### Step 2: Customize Colors
Edit the `themes.json` file to add your custom themes. Each theme includes:

#### Color Categories:
- **Base Colors**: `background`, `surface`, `primary`, `secondary`, `accent`
- **Text Colors**: `text_primary`, `text_secondary`, `text_disabled`, `text_inverse`
- **Interactive Colors**: `button_normal`, `button_hover`, `button_pressed`
- **Selection Colors**: `selection_background`, `selection_text`, `selection_inactive`, `hover_background`
- **Editor Colors**: `editor_background`, `editor_text`, `editor_line_number_bg`, `editor_line_number_text`, `editor_current_line`, `editor_selection`
- **Table Colors**: `table_background`, `table_alternate`, `table_header_bg`, `table_header_text`, `table_border`
- **Status Colors**: `success`, `warning`, `error`, `info`
- **UI Elements**: `splitter_handle`, `splitter_pressed`, `tab_active_bg`, `tab_active_text`, `tab_inactive_bg`, `tab_inactive_text`
- **Scrollbar Colors**: `scrollbar_background`, `scrollbar_handle`, `scrollbar_handle_hover`

#### Font and Layout Settings:
- **Fonts**: `font_family`, `font_size`, `editor_font_family`, `editor_font_size`
- **Layout**: `border_radius`, `border_width`, `padding_small`, `padding_medium`, `padding_large`
- **Animation**: `animation_duration`

### Step 3: Color Format
All colors should be in hex format (e.g., `#ffffff` for white, `#000000` for black).

## Example Custom Theme

This excerpt shows selected fields; start from a complete existing theme.

```json
{
  "My Custom Theme": {
    "name": "My Custom Theme",
    "colors": {
      "background": "#2d3748",
      "surface": "#4a5568",
      "primary": "#63b3ed",
      "accent": "#f56565",
      "text_primary": "#f7fafc",
      "selection_background": "#f56565",
      "selection_text": "#ffffff"
    },
    "font_family": "Arial",
    "font_size": 9,
    "editor_font_family": "Fira Code",
    "editor_font_size": 11
  }
}
```

## Syntax Highlighting

The YARA editor syntax highlighting automatically adapts to your chosen theme:

### Dark Themes
- Keywords: Blue (`#569cd6`)
- Logic operators: Purple (`#c586c0`)
- Built-ins: Teal (`#4ec9b0`)
- Strings: Orange (`#ce9178`)
- Comments: Green (`#6a9955`)

### Light Themes
- Keywords: Blue (`#0000ff`)
- Logic operators: Purple (`#af00db`)
- Built-ins: Teal (`#267f99`)
- Strings: Red (`#a31515`)
- Comments: Green (`#008000`)

## Theme File Location

In a source checkout, theme definitions are stored in `config/themes.json` at
the checkout root. The executable bundles this file as its theme defaults.

## Settings Storage

When running from source, your preferences are stored in `config/settings.json`
at the checkout root. Packaged builds use the `YaraXGUI` directory in your OS
configuration location (`%APPDATA%` on Windows, `~/Library/Application Support`
on macOS, or `$XDG_CONFIG_HOME` / `~/.config` on Linux).

## Tips for Creating Themes

1. **Start with an existing theme**: Copy the colors from Light or Dark theme and modify gradually
2. **Maintain contrast**: Ensure sufficient contrast between text and background colors for readability
3. **Test all widgets**: Check your theme with different data loaded to see how it looks in tables, trees, and editor
4. **Use consistent color families**: Choose colors that work well together
5. **Consider accessibility**: High contrast themes help users with visual impairments

## Troubleshooting

- If your theme doesn't load, check the JSON syntax in `config/themes.json`
- The application falls back to the Light theme if there are errors loading your custom theme
- Delete `config/settings.json` to reset to default settings
- Check the console output for error messages related to theme loading

## Available UI Elements That Support Theming

- Main window background
- Tables (hits, match details)
- Tree widgets (similar files, directory browser)
- Text editors (YARA editor, output areas)
- Buttons and interactive elements
- Tabs and tab bars
- Splitters and handles
- Headers and status bars
- Scrollbars
- Tooltips and dialogs

The theming system provides complete control over the visual appearance of YaraXGUI, allowing you to create a personalized and comfortable working environment.