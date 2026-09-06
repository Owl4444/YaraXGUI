from unittest.mock import Mock

import pytest
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QFileDialog, QMessageBox

import yaraxgui.repository.local_store as local_rule_store
from yaraxgui.app import MainWindow


@pytest.fixture
def window(app, tmp_path, monkeypatch):
    monkeypatch.setattr(MainWindow, "_settings_path", lambda self: tmp_path / "settings.json")
    monkeypatch.setattr(local_rule_store, "prepare_local_database", lambda: tmp_path / "rules.db")
    widget = MainWindow()
    yield widget
    for dock in widget._plugin_docks.values():
        repo = getattr(dock.widget(), "_local_repo", None)
        if repo:
            repo.close()
    widget.deleteLater()


def test_tab_switch_preserves_modifications_and_editor_listeners(window):
    first = window._editor_tabs.current_editor()
    first.insertPlainText("changed")
    listener = Mock()
    first.textChanged.connect(listener)
    window._editor_tabs.add_editor_tab()
    assert window._has_unsaved_changes()
    window._editor_tabs.setCurrentIndex(0)
    assert first.document().isModified()
    first.insertPlainText("again")
    listener.assert_called_once()


def _assert_default_dock_tabs(window, app):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QTabBar, QTabWidget

    window.show()
    app.processEvents()
    QTest.qWait(250)  # Allow Qt's dock transition animations to finish.
    expected = ['Scan Directory', 'Rule Repository', 'MWDB']
    group = [window.dock_scan_dir, *window.tabifiedDockWidgets(window.dock_scan_dir)]
    assert {dock.windowTitle() for dock in group if not dock.isHidden()} == set(expected)
    for dock in group:
        assert not dock.isFloating()
        assert window.dockWidgetArea(dock) == Qt.DockWidgetArea.RightDockWidgetArea
    assert window.dock_scan_results.isHidden()
    assert window.dock_rule_browser.isHidden()
    bars = [bar for bar in window.findChildren(QTabBar)
            if not bar.visibleRegion().isEmpty()
            and 'Scan Directory' in [bar.tabText(i) for i in range(bar.count())]]
    assert len(bars) == 1
    bar = bars[0]
    assert [bar.tabText(i) for i in range(bar.count())] == expected
    assert bar.tabText(bar.currentIndex()) == 'Scan Directory'
    assert window.tabPosition(Qt.DockWidgetArea.RightDockWidgetArea) == QTabWidget.TabPosition.South
    assert window.dock_scan_dir.visibleRegion().isEmpty() is False
    assert window._plugin_docks['rule_repository'].visibleRegion().isEmpty()
    assert window._plugin_docks['mwdb'].visibleRegion().isEmpty()


def test_fresh_layout_uses_scan_directory_with_plugin_tabs_below(window, app):
    _assert_default_dock_tabs(window, app)


def test_reset_layout_rejoins_floating_and_split_docks_without_losing_work(window, app):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QDockWidget, QLabel

    window.show()
    editor = window._editor_tabs.current_editor()
    editor.insertPlainText('unsaved rule changes')
    original = editor.toPlainText()
    repo = window._plugin_docks['rule_repository']
    mwdb = window._plugin_docks['mwdb']
    window.removeDockWidget(repo)
    window.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, repo)
    repo.show()
    mwdb.setFloating(True)
    window.dock_scan_results.show()
    window.splitDockWidget(window.dock_scan_dir, window.dock_scan_results, Qt.Orientation.Vertical)
    window.dock_rule_browser.show()
    window.dock_scan_dir.hide()
    extra = QDockWidget('Extra plugin', window)
    extra.setObjectName('dock_plugin_extra')
    extra.setWidget(QLabel('Extra content'))
    window._plugin_docks['extra'] = extra
    window.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, extra)
    extra.show()
    app.processEvents()

    for _ in range(2):
        window._reset_dock_layout()
        _assert_default_dock_tabs(window, app)
        assert extra.isHidden()
        assert editor.toPlainText() == original
        assert editor.document().isModified()

    # A hidden results panel reopens as a tab instead of another split pane.
    window.dock_scan_results.toggleViewAction().trigger()
    window.dock_scan_results.raise_()
    app.processEvents()
    assert not window.dock_scan_results.isHidden()
    assert window.dock_scan_results in window.tabifiedDockWidgets(window.dock_scan_dir)


def test_default_layout_can_be_saved_and_restored(window, app):
    window._reset_dock_layout()
    _assert_default_dock_tabs(window, app)
    saved = window.saveState()
    window._plugin_docks['mwdb'].setFloating(True)
    window.dock_scan_results.show()
    assert window.restoreState(saved)
    _assert_default_dock_tabs(window, app)


@pytest.mark.parametrize('confirm', [True, False])
def test_repository_save_button_updates_original_rule_without_file_dialog(window, monkeypatch, confirm):
    from PySide6.QtWidgets import QDialog
    from yaraxgui.repository.review import RuleUpdateReviewDialog
    monkeypatch.setattr(RuleUpdateReviewDialog, 'exec', lambda self:
                        QDialog.DialogCode.Accepted if confirm else QDialog.DialogCode.Rejected)
    dock = next(dock.widget() for dock in window._plugin_docks.values()
                if hasattr(dock.widget(), '_repo_add'))
    rid = dock._repo_add(name='sample', rule_text='rule sample { condition: true }')['id']
    dock._on_search()
    dock._table.setCurrentCell(0, 0)
    dock._on_load()
    editor = window._editor_tabs.current_editor()
    editor.insertPlainText('// changed\n')
    assert window.ui.pb_save_rule.text() == 'Update Repository'
    assert window.ui.pb_save_rule.isEnabled()
    monkeypatch.setattr(QFileDialog, 'getSaveFileName', Mock(side_effect=AssertionError('unexpected file dialog')))
    assert window.on_save_rule() is confirm
    assert (dock._repo_get(rid)['rule_text'] == editor.toPlainText()) is confirm
    assert editor.document().isModified() is not confirm


def test_settings_api_key_is_shared_with_existing_plugin_tabs(window, monkeypatch):
    import yaraxgui.credentials as credential_store
    from yaraxgui.ui.settings import SettingsDialog
    from PySide6.QtWidgets import QDialog

    secrets = {credential_store.API_SERVER_KEY: 'saved-test-key'}
    monkeypatch.setattr(credential_store, 'retrieve', lambda key: secrets.get(key, ''))
    monkeypatch.setattr(credential_store, 'store', lambda key, value: secrets.__setitem__(key, value))
    monkeypatch.setattr(credential_store, 'is_available', lambda: True)
    monkeypatch.setattr(window, '_apply_ui_font', Mock())
    monkeypatch.setattr(window, '_apply_editor_font', Mock())
    window._save_setting('repo_api_key', 'stale-legacy-test-key')

    for old, new in [('saved-test-key', 'replacement-test-key'), ('replacement-test-key', '')]:
        def edit(dialog):
            assert dialog._api_key_input.text() == old
            dialog._api_key_input.setText(new)
            return QDialog.DialogCode.Accepted
        monkeypatch.setattr(SettingsDialog, 'exec', edit)
        window._open_settings_dialog()
        assert credential_store.api_server_key(window._get_setting) == new
        assert window._get_setting('repo_api_key') == ''
        repository_checked = mwdb_checked = False
        for dock in window._plugin_docks.values():
            widget = dock.widget()
            if hasattr(widget, '_repo_stats'):
                repository_checked = True
                assert not hasattr(widget, '_key_input')
                assert credential_store.api_server_key(widget._get_setting) == new
            if hasattr(widget, '_api_headers'):
                mwdb_checked = True
                assert widget._api_headers().get('X-API-Key', '') == new
        assert repository_checked and mwdb_checked


def test_window_close_cancelled_save_keeps_all_tabs(window, monkeypatch):
    window._editor_tabs.current_editor().insertPlainText("changed")
    window._editor_tabs.add_editor_tab()
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Save)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a: ("", ""))
    event = QCloseEvent()
    window.closeEvent(event)
    assert not event.isAccepted()
    assert window._editor_tabs.count() == 2
    assert window._has_unsaved_changes()


def test_large_file_indicator_follows_active_tab(window):
    tabs = window._editor_tabs
    small = tabs.current_editor()
    large = tabs.add_editor_tab('x' * (64 * 1024 + 1))
    assert not window._large_file_indicator.isHidden()
    tabs.setCurrentWidget(small)
    assert window._large_file_indicator.isHidden()
    large.setPlainText('rule r {condition: true}')
    assert window._large_file_indicator.isHidden()
    tabs.setCurrentWidget(large)
    assert window._large_file_indicator.isHidden()
    large.insertPlainText('x' * (64 * 1024))
    assert not window._large_file_indicator.isHidden()
    large.undo()
    assert window._large_file_indicator.isHidden()


def test_file_and_help_menus_have_recovery_and_offline_topics(window):
    menus = {action.text():action.menu() for action in window.ui.menubar.actions() if action.menu()}
    assert {'File', 'View', 'Settings', 'Help'} <= menus.keys()
    assert 'Recover Unsaved Work…' in [action.text() for action in menus['File'].actions()]
    assert [action.text() for action in menus['Help'].actions() if not action.isSeparator()] == [
        'User Guide', 'YARA-X Reference', 'Keyboard Shortcuts', 'Recovery & Troubleshooting', 'About']


def test_draft_error_indicator_follows_active_tab(window):
    first = window._editor_tabs.current_editor()
    first._recovery.error = 'disk full'
    first._recovery.status_changed.emit('disk full')
    assert not window._draft_error_indicator.isHidden()

    second = window._editor_tabs.add_editor_tab()
    assert window._draft_error_indicator.isHidden()
    window._editor_tabs.setCurrentWidget(first)
    assert not window._draft_error_indicator.isHidden()


def test_editor_actions_are_above_editor_and_reset_is_in_file(window):
    assert all(button.isHidden() for button in (
        window.ui.pb_browse_yara, window.ui.pb_select_scan_dir, window.ui.pb_reset))
    for button in (window.ui.pb_save_rule, window.ui.pb_format_yara, window.ui.pb_scan):
        assert button.parentWidget() is window._editor_actions
        assert not button.isHidden()
    file_menu = next(action.menu() for action in window.ui.menubar.actions() if action.text() == 'File')
    assert 'Reset…' in [action.text() for action in file_menu.actions()]


def test_ui_font_preference_survives_theme_switch_and_rows_fit(window, app):
    from PySide6.QtWidgets import QLineEdit, QLabel, QDialog
    window._save_setting('ui_font_family', app.font().family())
    window._save_setting('ui_font_size', 14)
    window.apply_theme('Dark')
    window.show()
    app.processEvents()
    field = QLineEdit(window)
    label = QLabel('Example', window)
    dialog = QDialog(window)
    for widget in (field, label, dialog, window.ui.pb_scan,
                   window.ui.tv_file_hits, window.ui.tv_file_hits.horizontalHeader()):
        widget.ensurePolished()
        assert widget.font().pointSize() == 14
    view = window.ui.tv_file_hits
    assert view.verticalHeader().defaultSectionSize() >= view.fontMetrics().height() + 8
    window.apply_theme('Light')
    assert app.font().pointSize() == 14
    assert window._editor_tabs.current_editor().font().pointSize() != 14
