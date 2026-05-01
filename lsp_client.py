"""LSP client for yr-ls (YARA-X Language Server).

Manages the yr-ls subprocess via QProcess and speaks JSON-RPC 2.0
over stdio with ``Content-Length`` framing.  All I/O is async through
Qt signals — no threads required.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QTimer, Signal


class LspClient(QObject):
    """Async LSP client that drives a single yr-ls.exe process."""

    # -- Signals --------------------------------------------------------
    completions_received = Signal(int, list)   # (request_id, items)
    diagnostics_received = Signal(str, list)   # (document_uri, diags)
    server_ready = Signal()
    server_error = Signal(str)

    def __init__(self, yr_ls_path: str, parent: QObject | None = None):
        super().__init__(parent)
        self._yr_ls_path = yr_ls_path
        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)

        self._request_id = 0
        self._pending: dict[int, str] = {}  # id → method name
        self._read_buffer = bytearray()
        self._initialized = False
        self._open_documents: dict[str, int] = {}  # uri → version

        self._restart_count = 0
        self._max_restarts = 3

        # Wire QProcess signals
        self._process.readyReadStandardOutput.connect(self._on_stdout)
        self._process.finished.connect(self._on_finished)
        self._process.errorOccurred.connect(self._on_error)

    # -- Public API -----------------------------------------------------

    @property
    def is_ready(self) -> bool:
        return (self._initialized
                and self._process.state() == QProcess.ProcessState.Running)

    def start(self):
        """Launch yr-ls and perform the LSP handshake."""
        if not Path(self._yr_ls_path).exists():
            self.server_error.emit(f"yr-ls not found: {self._yr_ls_path}")
            return
        self._process.start(self._yr_ls_path, [])
        if not self._process.waitForStarted(5000):
            self.server_error.emit("yr-ls failed to start")
            return
        self._send_initialize()

    def stop(self):
        """Gracefully shut down yr-ls."""
        if self._process.state() == QProcess.ProcessState.NotRunning:
            return
        self._send_request("shutdown", {})
        self._send_notification("exit", None)
        if not self._process.waitForFinished(3000):
            self._process.kill()
            self._process.waitForFinished(1000)
        self._initialized = False

    # -- Document lifecycle ---------------------------------------------

    def did_open(self, uri: str, text: str, language_id: str = "yara"):
        if not self.is_ready:
            return
        self._open_documents[uri] = 1
        self._send_notification("textDocument/didOpen", {
            "textDocument": {
                "uri": uri,
                "languageId": language_id,
                "version": 1,
                "text": text,
            }
        })

    def did_change(self, uri: str, text: str):
        if not self.is_ready or uri not in self._open_documents:
            return
        self._open_documents[uri] += 1
        self._send_notification("textDocument/didChange", {
            "textDocument": {
                "uri": uri,
                "version": self._open_documents[uri],
            },
            "contentChanges": [{"text": text}],
        })

    def did_close(self, uri: str):
        if not self.is_ready or uri not in self._open_documents:
            return
        self._send_notification("textDocument/didClose", {
            "textDocument": {"uri": uri},
        })
        self._open_documents.pop(uri, None)

    # -- Requests -------------------------------------------------------

    def request_completion(self, uri: str, line: int, character: int) -> int:
        """Send textDocument/completion. Returns the request ID."""
        return self._send_request("textDocument/completion", {
            "textDocument": {"uri": uri},
            "position": {"line": line, "character": character},
        })

    # -- JSON-RPC transport ---------------------------------------------

    def _send_request(self, method: str, params) -> int:
        self._request_id += 1
        rid = self._request_id
        self._pending[rid] = method
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self._write_message(msg)
        return rid

    def _send_notification(self, method: str, params):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._write_message(msg)

    def _write_message(self, msg: dict):
        body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        self._process.write(header + body)

    # -- Receiving ------------------------------------------------------

    def _on_stdout(self):
        self._read_buffer += bytes(self._process.readAllStandardOutput())
        while True:
            # Look for the header/body boundary
            sep = self._read_buffer.find(b"\r\n\r\n")
            if sep < 0:
                break
            # Parse Content-Length from header
            header = self._read_buffer[:sep].decode("ascii", errors="replace")
            content_length = 0
            for line in header.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":", 1)[1].strip())
                    break
            if content_length == 0:
                # Malformed — skip this header
                self._read_buffer = self._read_buffer[sep + 4:]
                continue
            body_start = sep + 4
            body_end = body_start + content_length
            if len(self._read_buffer) < body_end:
                break  # incomplete body, wait for more data
            body = self._read_buffer[body_start:body_end]
            self._read_buffer = self._read_buffer[body_end:]
            try:
                msg = json.loads(body)
            except json.JSONDecodeError:
                continue
            self._dispatch(msg)

    def _dispatch(self, msg: dict):
        if "id" in msg and "method" not in msg:
            # Response to a request we sent
            rid = msg["id"]
            method = self._pending.pop(rid, "")
            if method == "initialize":
                self._on_initialize_response(msg)
            elif method == "textDocument/completion":
                self._on_completion_response(rid, msg)
        elif "method" in msg:
            # Server notification
            method = msg["method"]
            params = msg.get("params", {})
            if method == "textDocument/publishDiagnostics":
                uri = params.get("uri", "")
                diags = params.get("diagnostics", [])
                self.diagnostics_received.emit(uri, diags)

    # -- Handshake ------------------------------------------------------

    def _send_initialize(self):
        self._send_request("initialize", {
            "processId": os.getpid(),
            "capabilities": {
                "textDocument": {
                    "completion": {
                        "completionItem": {
                            "snippetSupport": True,
                        }
                    },
                    "publishDiagnostics": {
                        "relatedInformation": True,
                    },
                }
            },
            "rootUri": None,
        })

    def _on_initialize_response(self, msg: dict):
        if "error" in msg:
            self.server_error.emit(
                f"LSP initialize failed: {msg['error']}")
            return
        # Send the initialized notification
        self._send_notification("initialized", {})
        self._initialized = True
        self._restart_count = 0
        self.server_ready.emit()

    # -- Completion response --------------------------------------------

    def _on_completion_response(self, rid: int, msg: dict):
        result = msg.get("result")
        if result is None:
            self.completions_received.emit(rid, [])
            return
        # result can be a list or {"isIncomplete": bool, "items": [...]}
        if isinstance(result, list):
            items = result
        else:
            items = result.get("items", [])
        self.completions_received.emit(rid, items)

    # -- Error / restart ------------------------------------------------

    def _on_finished(self, exit_code, exit_status):
        self._initialized = False
        self._pending.clear()
        if self._restart_count < self._max_restarts:
            self._restart_count += 1
            QTimer.singleShot(3000, self.start)
            self.server_error.emit(
                f"yr-ls exited (code {exit_code}), restarting "
                f"({self._restart_count}/{self._max_restarts})...")
        else:
            self.server_error.emit(
                f"yr-ls exited (code {exit_code}), max restarts reached")

    def _on_error(self, error):
        self.server_error.emit(f"yr-ls process error: {error}")
