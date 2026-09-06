import pytest
import yara_x
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("YARAXGUI_UPLOAD_DIR", str(tmp_path / "uploads"))
    from api import yaraxgui_api
    with TestClient(yaraxgui_api.app, client=('127.0.0.1', 50000), base_url='http://localhost') as client:
        yield client


def test_format_with_binding_and_comment_markers(client):
    source = '''rule r { meta: url = "https://host/*literal*/"
        condition: with size = filesize : (size == 2) // retain this
    }'''
    response = client.post("/rules/format", json={"rule_text": source})
    assert response.status_code == 200
    body = response.json()
    assert body["success"]
    assert "// retain this" in body["formatted"]
    rules = yara_x.compile(body["formatted"])
    assert rules.scan(b"AB").matching_rules
    assert list(rules)[0].metadata == (("url", "https://host/*literal*/"),)


def test_format_preserves_original_compiler_error(client):
    response = client.post("/rules/format", json={
        "rule_text": "rule r { condition: with size = filesize : (unknown == 2) }"})
    body = response.json()
    assert body["success"] is False
    assert not body["formatted"]
    assert "unknown" in body["error"]


def test_api_rejects_oversized_format_without_output(client):
    body = client.post("/rules/format", json={"rule_text": "x" * (256 * 1024 + 1)}).json()
    assert body["success"] is False
    assert not body["formatted"]
    assert "256 KiB" in body["error"]


def test_remote_includes_are_disabled(client, tmp_path):
    included = tmp_path / "common.yar"
    included.write_text('rule secret_name {condition: true}')
    source = f'include "{included}"\nrule root {{condition: true}}'
    validation = client.post("/rules/validate", json={"rule_text": source}).json()
    assert not validation["valid"]
    result = client.post("/rules/format", json={"rule_text": source}).json()
    assert not result["success"]
    assert "secret_name" not in str(validation) + str(result)


def test_formatting_does_not_block_api_event_loop(client, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    import time
    from api import yaraxgui_api
    started, release = threading.Event(), threading.Event()
    def slow_format(operation, payload, **kwargs):
        started.set()
        assert release.wait(4)
        return payload["text"]
    monkeypatch.setattr(yaraxgui_api._runner, "run", slow_format)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client.post, "/rules/format", json={"rule_text": "rule r {condition: true}"})
        try:
            assert started.wait(2)
            start = time.monotonic()
            response = client.get("/health")
            assert response.status_code == 200
            assert time.monotonic() - start < 1
        finally:
            release.set()
        assert pending.result().json()["success"]
