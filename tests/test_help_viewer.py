from PySide6.QtTest import QTest
from yaraxgui.ui.help import HelpViewer, documentation_pages


def _load_pages(viewer):
    # QTest.qWait can retain the GIL and starve the Python document-loading
    # thread when run in the full suite. Wait for that worker explicitly, then
    # deliver its result through the same callback the GUI timer uses.
    viewer._future.result(timeout=10)
    viewer._loaded()
    QTest.qWait(20)
    assert viewer._pages


def test_offline_reference_includes_syntax_modules_and_recovery():
    pages = documentation_pages()
    assert len(pages) > 50
    assert any('Recovery' in title for title, _, _ in pages)
    assert any('Modules / pe' in title for title, _, _ in pages)
    assert any('with' in body for title, _, body in pages if 'conditions' in title)


def test_help_search_reads_bundled_content(app):
    viewer = HelpViewer('Recovery & Troubleshooting')
    viewer.show()
    _load_pages(viewer)
    assert 'Recover unsaved work' in viewer._browser.toPlainText()
    viewer._search.setText('raw_data_offset')
    viewer._filter()
    assert viewer._visible
    assert all('raw_data_offset' in viewer._searchable[i] for i in viewer._visible)
    viewer.close()


def test_find_in_page_shortcuts_navigation_and_no_matches(app):
    from PySide6.QtCore import Qt
    viewer = HelpViewer()
    viewer.show()
    viewer.activateWindow()
    _load_pages(viewer)
    viewer._browser.setPlainText('Alpha beta alpha')
    viewer._browser.setFocus()
    QTest.keyClick(viewer._browser, Qt.Key.Key_F, Qt.KeyboardModifier.ControlModifier)
    assert not viewer._find_bar.isHidden()
    assert viewer._find_text.hasFocus()
    viewer._find_text.setText('alpha')
    assert viewer._browser.textCursor().selectionStart() == 0
    QTest.keyClick(viewer._find_text, Qt.Key.Key_Return)
    assert viewer._browser.textCursor().selectionStart() == 11
    QTest.keyClick(viewer._find_text, Qt.Key.Key_Return)
    assert viewer._browser.textCursor().selectionStart() == 0
    assert 'Wrapped' in viewer._find_status.text()
    QTest.keyClick(viewer._find_text, Qt.Key.Key_Return, Qt.KeyboardModifier.ShiftModifier)
    assert viewer._browser.textCursor().selectionStart() == 11
    viewer._find_text.setText('unfindable')
    assert viewer._find_status.text() == 'No matches'
    viewer._find_text.clear()
    assert not viewer._find_status.text()
    QTest.keyClick(viewer._find_text, Qt.Key.Key_Escape)
    assert viewer._find_bar.isHidden()
    assert viewer.isVisible()
    viewer.close()


def test_upstream_links_and_callouts_work_offline(app):
    from PySide6.QtCore import QUrl
    pages = documentation_pages()
    assert not any('{{<' in body for _, _, body in pages)
    syntax = next(body for _, path, body in pages if path.name == 'syntax.md')
    conditions = next(path for _, path, _ in pages if path.name == 'conditions.md')
    assert conditions.as_uri() in syntax
    viewer = HelpViewer()
    viewer.show()
    _load_pages(viewer)
    viewer._search.setText('syntax')
    viewer._link(QUrl(conditions.as_uri()))
    QTest.qWait(250)
    assert viewer._current_path == conditions
    assert '**Warning**' in next(body for _, path, body in pages if path == conditions)
    viewer.close()
