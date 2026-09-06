from hex_editor.hex_editor_window import HexEditorWindow


def test_hex_menus_group_tasks_and_share_toolbar_actions(app):
    window = HexEditorWindow()
    try:
        menus = {action.text().replace('&', ''): action.menu()
                 for action in window.menuBar().actions() if action.menu()}
        assert list(menus) == ['File', 'Edit', 'Navigate', 'Analyze', 'View']
        assert window._goto_action in menus['Navigate'].actions()
        assert window._find_action in menus['Navigate'].actions()
        assert window._transform_action in menus['Analyze'].actions()
        assert window._open_action in window._main_toolbar.actions()
        assert window._find_action in window._main_toolbar.actions()
        assert window._goto_action not in menus['Edit'].actions()
        assert window._view_toggle_btn is window._toggle_view_action
        assert window._escape_text_action is window._toggle_escape_action
        assert any(action.menu() and action.text() == 'Layout' for action in menus['View'].actions())
        assert window._navigation_toolbar.isHidden()
        window._file_list = ['first', 'second']
        window._file_index = 0
        window._update_nav_ui()
        assert not window._navigation_toolbar.isHidden()
        assert window._next_action.isEnabled()
        window._toggle_view_action.setChecked(True)
        assert window._hex_widget._text_mode
        window._toggle_view_action.setChecked(False)
        window._hex_widget.read_only = False
        assert not window._lock_action.isChecked()
        assert window._status_mode.text() == 'Editable'
        window._lock_action.trigger()
        assert window._hex_widget.read_only
        assert window._status_mode.text() == 'Read-Only'
        window._bpl_spin.setValue(24)
        assert window._hex_widget.bytes_per_line() == 24
    finally:
        window.close()
        window.deleteLater()
