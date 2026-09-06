import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.rule_repo import RuleRepository
from plugins import rule_repository


@pytest.fixture
def client(tmp_path, monkeypatch):
    repo = RuleRepository(tmp_path / "rules.db")
    monkeypatch.setattr(rule_repository, "_repo", repo)
    app = FastAPI()
    for route in rule_repository.plugin.spec.api_routes:
        app.add_api_route(route.path, route.handler, methods=[route.method])
    with TestClient(app) as client:
        yield client
    repo.close()


def test_missing_rule_returns_404_after_other_writes(client):
    assert client.post("/repo/rules", json={"name": "sample", "rule_text": "text"}).status_code == 200
    assert client.put("/repo/rules/999", json={"name": "missing"}).status_code == 404
    assert client.delete("/repo/rules/999").status_code == 404


def test_duplicate_update_returns_conflict_without_breaking_next_write(client):
    first = client.post("/repo/rules", json={"name": "first", "rule_text": "text"}).json()["id"]
    second = client.post("/repo/rules", json={"name": "second", "rule_text": "text"}).json()["id"]
    assert client.put(f"/repo/rules/{second}", json={"name": "first"}).status_code == 409
    assert client.delete(f"/repo/rules/{first}").status_code == 200


def test_search_with_family_and_invalid_query(client):
    client.post("/repo/rules", json={"name": "needle", "rule_text": "text", "family": "sample"})
    response = client.get("/repo/rules", params={"q": "needle", "family": "sample"})
    assert response.status_code == 200
    assert response.json()[0]["name"] == "needle"
    assert client.get("/repo/rules", params={"q": '"'}).status_code == 400


def test_conditional_rule_update_rejects_stale_drafts(client):
    rid = client.post('/repo/rules', json={'name': 'sample', 'rule_text': 'original'}).json()['id']
    url = f'/repo/rules/{rid}'
    assert client.put(url, json={'rule_text': 'first edit', 'expected_rule_text': 'original'}).status_code == 200
    assert client.put(url, json={'rule_text': 'stale edit', 'expected_rule_text': 'original'}).status_code == 409
    assert client.get(url).json()['rule_text'] == 'first edit'
    assert client.put(url, json={'expected_rule_text': 'first edit'}).status_code == 400


def test_remote_pagination_allows_desktop_lookahead(client):
    # The desktop requests 200 visible rows plus one to detect another page.
    assert client.get('/repo/rules?limit=201').status_code == 200


def test_search_budget_stops_before_materializing_all_matching_rules(tmp_path):
    repo = RuleRepository(tmp_path / 'bounded.db')
    try:
        for i in range(20):
            repo.add(name=f'r{i}', rule_text='x' * 10000)
        with pytest.raises(OverflowError):
            repo.search(limit=20, max_bytes=15000)
        assert len(repo.search(limit=1, max_bytes=15000)) == 1
    finally:
        repo.close()
