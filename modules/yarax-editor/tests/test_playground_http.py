"""Exercise actual HTTP requests, including browser Origin and hostile hosts."""
from http.client import HTTPConnection
from importlib.resources import files
import json
from pathlib import Path
import threading

import pytest

from yarax_editor.playground import create_server


@pytest.fixture
def legacy_windows_encoding(monkeypatch):
    """Model Windows-1252 defaults even when pytest runs on a UTF-8 system."""
    original = Path.open

    def open_file(path, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        if "b" not in mode and encoding is None:
            encoding = "cp1252"
        return original(path, mode, buffering, encoding, errors, newline)

    monkeypatch.setattr(Path, "open", open_file)


@pytest.fixture(scope="module")
def server():
    server = create_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()


def request(server, method="GET", path="/", headers=None, body=None):
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_all_interfaces_and_loopback_page(server):
    assert server.server_address[0] == "0.0.0.0"
    status, body = request(server)
    assert status == 200
    assert b"YARA" in body


def test_page_unicode_matches_its_declared_encoding(server, legacy_windows_encoding):
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read()
        assert response.status == 200
        assert response.getheader("Content-Type") == "text/html; charset=utf-8"
        assert int(response.getheader("Content-Length")) == len(body)
        text = body.decode("utf-8")
        assert "LOCAL · 1.20.0" in text
        assert "Standalone language toolkit · integration preview" in text
        assert "Â·" not in text
    finally:
        connection.close()


def test_catalog_unicode_ignores_system_encoding(legacy_windows_encoding):
    from yarax_editor.catalog import load_catalog

    expected = json.loads(files("yarax_editor").joinpath("data/catalog.json").read_bytes().decode("utf-8"))
    load_catalog.cache_clear()
    try:
        assert load_catalog() == expected
    finally:
        load_catalog.cache_clear()


def test_reference_unicode_ignores_system_encoding(tmp_path, monkeypatch, legacy_windows_encoding):
    from yarax_editor.catalog import Catalog

    catalog = Catalog()
    reference = tmp_path / "data/reference"
    reference.mkdir(parents=True)
    markdown = "# Café · 日本語\n\nReference → résumé 😀\n"
    (reference / "unicode.md").write_bytes(markdown.encode("utf-8"))
    monkeypatch.setattr("yarax_editor.catalog.files", lambda package: tmp_path)
    results = catalog.search_docs("日本語")
    assert len(results) == 1
    assert results[0]["markdown"] == markdown


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_same_origin_compiler_request(server, host):
    authority = f"{host}:{server.server_port}"
    status, body = request(server, "POST", "/api/analyze",
        {"Host": authority, "Origin": "http://" + authority, "Content-Type": "application/json"},
        json.dumps({"text": "rule r {condition: with n = filesize : (n > 0)}"}))
    assert status == 200
    assert json.loads(body)["valid"] is True


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("kind", ["foreign_host", "foreign_origin", "null_origin", "wrong_port"])
def test_reject_untrusted_request(server, method, kind):
    authority = f"127.0.0.1:{server.server_port}"
    headers = {"Host": authority, "Origin": "http://" + authority}
    if kind == "foreign_host":
        headers = {"Host": "attacker.invalid", "Origin": "http://attacker.invalid"}
    elif kind == "foreign_origin":
        headers["Origin"] = "http://attacker.invalid"
    elif kind == "null_origin":
        headers["Origin"] = "null"
    else:
        headers["Host"] = "127.0.0.1:1"
    assert request(server, method, headers=headers, body="{}")[0] == 403


@pytest.mark.parametrize("path", ["format", "analyze", "complete"])
def test_oversized_source_is_rejected(server, path):
    status, body = request(server, "POST", "/api/" + path,
        body=json.dumps({"text": "x" * (256 * 1024 + 1)}))
    assert status == 413
    assert "256 KiB" in json.loads(body)["error"]


def test_format_worker_via_http(server):
    status, body = request(server, "POST", "/api/format",
        body=json.dumps({"text": "rule r {condition: true}"}))
    assert status == 200
    assert json.loads(body)["text"] == "rule r {\n    condition:\n        true\n}\n"


def test_non_object_request_returns_error(server):
    assert request(server, "POST", "/api/format", body="[]")[0] == 400


@pytest.mark.parametrize("error,status", [("FormatBusy", 429), ("FormatTimeout", 504)])
def test_format_limit_errors_are_reported(server, monkeypatch, error, status):
    from yarax_editor import formatting_jobs

    def fail(*args, **kwargs):
        raise getattr(formatting_jobs, error)("Original source retained")

    monkeypatch.setattr(formatting_jobs.FormatRunner, "format", fail)
    actual, body = request(server, "POST", "/api/format", body='{"text":"rule r {condition: true}"}')
    assert actual == status
    assert json.loads(body)["error"] == "Original source retained"
