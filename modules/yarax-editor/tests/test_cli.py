from pathlib import Path
from yarax_editor.cli import main


def test_demo_bind_default_and_override(monkeypatch):
    calls = []
    monkeypatch.setattr("yarax_editor.playground.serve", lambda port, host: calls.append((host, port)))
    assert main(["demo"]) == 0
    assert main(["demo", "--host", "127.0.0.1", "--port", "9876"]) == 0
    assert calls == [("0.0.0.0", 8765), ("127.0.0.1", 9876)]


def test_cli_format_check_and_info(tmp_path, capsys):
    source = tmp_path / "rule.yar"
    original = "rule r {condition: with n = filesize : (n > 0)}"
    source.write_text(original)
    assert main(["check", str(source)]) == 0
    assert '"valid": true' in capsys.readouterr().out
    assert main(["format", str(source)]) == 0
    assert "\n    condition:" in capsys.readouterr().out
    assert source.read_text() == original
    assert main(["info"]) == 0
    assert '"engine": "1.20.0"' in capsys.readouterr().out


def test_cli_reports_invalid_source_and_invalid_utf8(tmp_path, capsys):
    source = tmp_path / "rule.yar"
    source.write_text("rule r {condition: missing}")
    assert main(["format", str(source)]) == 1
    assert "missing" in capsys.readouterr().err
    source.write_bytes(b"\xff")
    assert main(["check", str(source)]) == 1
    assert "decode" in capsys.readouterr().err


def test_cli_globals_and_completion(tmp_path, capsys):
    source = tmp_path / "rule.yar"
    source.write_text("rule r {condition: limit > 0}")
    assert main(["check", str(source), "--globals", '{"limit":1}']) == 0
    capsys.readouterr()
    text = 'import "math" rule r {condition: math.ent'
    source.write_text(text)
    assert main(["complete", str(source), "--offset", str(len(text))]) == 0
    assert "entropy" in capsys.readouterr().out
