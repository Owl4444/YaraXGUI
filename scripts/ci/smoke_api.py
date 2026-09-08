"""Check a running development API from inside its headless environment."""

from importlib.util import find_spec
import json
import os
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


def request(path, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    port = int(os.environ.get("YARAXGUI_PORT", "7777"))
    req = Request(f"http://127.0.0.1:{port}" + path, data=body,
                  headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=10) as response:
        return json.load(response)


def main():
    # mwdblib installs keyring transitively, even in the server-only environment.
    for module in ("PySide6", "PyInstaller"):
        assert find_spec(module) is None, f"Desktop dependency in API image: {module}"

    deadline = time.monotonic() + 60
    while True:
        try:
            assert request("/health") == {"status": "ok"}
            break
        except (URLError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)

    source = "rule ci_smoke {condition: with n = filesize : (n > 0)}"
    compiled = request("/rules/compile", {"rule_text": source})
    assert compiled["success"], compiled
    assert compiled["rules_count"] == 1, compiled
    invalid = request("/rules/validate", {"rule_text": "rule broken {condition: missing}"})
    assert invalid["valid"] is False, invalid
    formatted = request("/rules/format", {"rule_text": source})
    assert formatted["success"], formatted
    assert "\n    condition:" in formatted["formatted"], formatted
    validated = request("/rules/validate", {"rule_text": formatted["formatted"]})
    assert validated["valid"], validated
    stats = request("/repo/stats")
    assert stats["total_rules"] == 0, stats
    print("Headless API: startup, compilation, validation, formatting and repository passed")


if __name__ == "__main__":
    main()
