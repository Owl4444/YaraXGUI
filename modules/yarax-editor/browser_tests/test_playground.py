import threading
import pytest
from playwright.sync_api import sync_playwright, expect
from yarax_editor.playground import create_server


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def page(browser):
    server = create_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(f"http://127.0.0.1:{server.server_port}")
    expect(page.locator("#status")).to_have_text("Valid YARA-X rule")
    yield page
    assert not errors
    page.close()
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()


def test_live_diagnostics_highlighting_formatting_and_docs(page):
    source = page.get_by_role("textbox", name="YARA source")
    source.fill('rule r { meta: url = "https://host/*literal*/" condition: with size = filesize : (size > 0) }')
    expect(page.locator("#status")).to_have_text("Valid YARA-X rule")
    expect(page.locator("#paint .string")).to_have_text('"https://host/*literal*/"')
    page.get_by_role("button", name="Format", exact=True).click()
    expect(source).to_have_value('rule r {\n    meta:\n        url = "https://host/*literal*/"\n    condition:\n        with size = filesize: (size > 0)\n}\n')
    source.fill('rule r { meta: label = "😀" condition: missing }')
    expect(page.locator("#issues")).to_contain_text("unknown identifier")
    page.locator("#issues li").first.click()
    assert source.evaluate("e => e.value.slice(e.selectionStart,e.selectionEnd)") == "missing"
    page.get_by_role("button", name="Offline reference").click()
    page.get_by_role("textbox", name="Search reference").fill("with")
    page.get_by_role("button", name="Search", exact=True).click()
    expect(page.locator("#docresults")).to_contain_text("with")


def test_header_displays_unicode_separators(page):
    expect(page.locator(".badge")).to_have_text("LOCAL · 1.20.0")
    expect(page.locator("header small")).to_have_text("Standalone language toolkit · integration preview")


def test_completion_dismissal_and_nested_fields(page):
    source = page.get_by_role("textbox", name="YARA source")
    source.fill('rule r { condition: fil')
    expect(page.get_by_role("listbox", name="Suggestions")).to_be_visible()
    source.press_sequentially("esize", delay=20)
    expect(page.get_by_role("listbox", name="Suggestions")).to_be_hidden()
    source.fill('import "pe" rule r { condition: pe.sections[0].raw')
    expect(page.get_by_role("listbox", name="Suggestions")).to_contain_text("raw_data_offset")
    source.press("ArrowDown")
    source.press("Enter")
    expect(source).to_have_value('import "pe" rule r { condition: pe.sections[0].raw_data_size')
    source.fill('// import "p')
    source.press("Control+Space")
    expect(page.get_by_role("listbox", name="Suggestions")).to_be_hidden()


def test_rule_snippet_mirrors_and_signature_help(page):
    source = page.get_by_role("textbox", name="YARA source")
    source.fill('ru')
    source.press("Control+Space")
    expect(page.get_by_role("listbox", name="Suggestions")).to_contain_text("rule")
    source.press("Enter")
    expect(source).to_have_value('rule rule_name {\n    strings:\n        $a = "text"\n    condition:\n        $a\n}\n')
    source.press("Tab")
    source.press_sequentially("sig")
    expect(source).to_have_value('rule rule_name {\n    strings:\n        $sig = "text"\n    condition:\n        $sig\n}\n')
    source.fill('import "pe" rule r { condition: pe.imports("kernel32.dll", ')
    source.press("Control+Space")
    expect(page.locator("#details")).to_contain_text("Argument 2")


def test_delayed_completion_cannot_reopen_after_escape(page):
    source = page.get_by_role("textbox", name="YARA source")
    routes = []
    page.route("**/api/complete", lambda route: routes.append(route))
    source.fill('rule r { condition: fil')
    with page.expect_request("**/api/complete"):
        source.press("Control+Space")
    source.press("Escape")
    for route in routes:
        route.fulfill(json={"items": [{"label": "filesize", "kind": "keyword", "edit": {"span": {"start": 20, "end": 23}, "text": "filesize"}}]})
    page.unroute("**/api/complete")
    expect(page.get_by_role("listbox", name="Suggestions")).to_be_hidden()


@pytest.mark.parametrize("failure", [False, True])
def test_format_requests_are_single_and_stale_results_are_ignored(page, failure):
    source = page.get_by_role("textbox", name="YARA source")
    routes = []
    page.route("**/api/format", lambda route: routes.append(route))
    with page.expect_request("**/api/format"):
        source.press("Control+Shift+F")
    expect(page.locator("#format")).to_be_disabled()
    expect(page.locator("#format")).to_have_text("Formatting…")
    for _ in range(5):
        source.press("Control+Shift+F")
    edited = 'rule edited {condition: true}'
    source.fill(edited)
    expect(page.locator("#status")).to_have_text("Valid YARA-X rule")
    assert len(routes) == 1
    if failure:
        routes[0].fulfill(status=504, json={"error": "An old formatting timeout"})
    else:
        routes[0].fulfill(json={"text": "rule old {condition: false}"})
    expect(page.locator("#format")).to_be_enabled()
    expect(source).to_have_value(edited)
    expect(page.locator("#status")).to_have_text("Valid YARA-X rule")
    page.unroute("**/api/format")
    page.locator("#format").click()
    expect(source).to_have_value('rule edited {\n    condition:\n        true\n}\n')


def test_large_file_uses_manual_actions_and_huge_file_stays_local(page):
    source = page.get_by_role("textbox", name="YARA source")
    calls = []

    def respond(route):
        calls.append(route.request.url.rsplit('/', 1)[-1])
        route.fulfill(json={"valid": True, "diagnostics": [], "highlights": [], "items": []})

    page.route("**/api/*", respond)
    large = '// ' + 'a' * (70 * 1024) + '\nrule r {condition: true}'
    source.fill(large)
    expect(page.locator("#status")).to_contain_text("Large file")
    source.click()
    page.wait_for_timeout(450)
    assert calls == []
    assert source.evaluate("e => getComputedStyle(e).color") != 'rgba(0, 0, 0, 0)'
    assert page.locator("#paint").text_content() == ''
    page.locator("#check").click()
    expect(page.locator("#status")).to_have_text("Valid YARA-X rule")
    assert calls == ['analyze']
    source.press("Control+Space")
    page.wait_for_timeout(150)
    assert calls == ['analyze', 'complete']
    calls.clear()
    # Non-ASCII source exceeds the byte budget even below the character limit.
    huge = '😀' * 70000
    source.fill(huge)
    page.locator("#format").click()
    page.locator("#check").click()
    source.press("Control+Space")
    expect(page.locator("#status")).to_contain_text("256 KiB")
    page.wait_for_timeout(450)
    assert calls == []
    expect(source).to_have_value(huge)
    with page.expect_download() as download:
        page.locator("#download").click()
    assert download.value.suggested_filename == 'rule.yar'
    source.fill('rule small {condition: true}')
    expect(page.locator("#status")).to_have_text("Valid YARA-X rule")
    assert 'analyze' in calls


def test_format_failure_preserves_source_and_reenables_button(page):
    source = page.get_by_role("textbox", name="YARA source")
    original = source.input_value()
    page.route("**/api/format", lambda route: route.fulfill(status=504,
        json={"error": "Formatting exceeded 5 seconds; original source retained"}))
    page.locator("#format").click()
    expect(page.locator("#status")).to_contain_text("exceeded 5 seconds")
    expect(page.locator("#format")).to_be_enabled()
    expect(source).to_have_value(original)
