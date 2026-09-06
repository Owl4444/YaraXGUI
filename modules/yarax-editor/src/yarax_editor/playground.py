"""Browser demo, independent of YaraXGUI. No CDN or third-party service."""
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
from ipaddress import ip_address
from .editing import expand_snippet
from .formatter import FormatError
from .formatting_jobs import (FormatRunner, FormatBusy, FormatTimeout,
    SourceTooLarge, check_source_size, MAX_INTERACTIVE_BYTES, MAX_AUTOMATIC_BYTES)
from .service import LanguageService


def create_server(port=0, host="0.0.0.0"):
    service = LanguageService()
    formatter = FormatRunner()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, data, status=200, content_type="application/json"):
            body = (data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def allowed_request(self):
            # Accepted sockets identify the destination interface even when the
            # listener binds all interfaces. Keep Host checks against DNS rebinding.
            destination = self.connection.getsockname()[0]
            names = {destination}
            if ip_address(destination).is_loopback:
                names.add("localhost")
            if host != "0.0.0.0":
                names.add(host.lower())
            port = self.server.server_port
            authorities = {f"{name}:{port}" for name in names}
            if port == 80:
                authorities.update(names)
            authority = self.headers.get("Host", "").lower()
            origin = self.headers.get("Origin")
            return (len(self.headers.get_all("Host", [])) == 1
                and len(self.headers.get_all("Origin", [])) <= 1
                and authority in authorities
                and origin in (None, "http://" + authority))

        def do_GET(self):
            if not self.allowed_request():
                self.respond({"error": "Host or origin is not allowed"}, 403)
            elif self.path == "/":
                html = files("yarax_editor").joinpath("data/playground.html").read_text(encoding="utf-8")
                html = html.replace("__MAX_INTERACTIVE_BYTES__", str(MAX_INTERACTIVE_BYTES))
                html = html.replace("__MAX_AUTOMATIC_BYTES__", str(MAX_AUTOMATIC_BYTES))
                self.respond(html, content_type="text/html")
            else:
                self.respond({"error": "Not found"}, 404)

        def do_POST(self):
            if not self.allowed_request():
                self.respond({"error": "Host or origin is not allowed"}, 403)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 2_000_000:
                    self.respond({"error": "Request exceeds demo size limit"}, 413)
                    return
                data = json.loads(self.rfile.read(size))
                if not isinstance(data, dict):
                    raise ValueError("Expected a JSON object")
                text = data.get("text", "")
                offset = data.get("offset", 0)
                if not isinstance(text, str) or not isinstance(offset, int) or not 0 <= offset <= len(text):
                    raise ValueError("Invalid document or offset")
                check_source_size(text)
                if self.path == "/api/analyze":
                    validation = service.compiler.validate(text)
                    self.respond({"valid": validation.valid, "diagnostics": [asdict(d) for d in validation.diagnostics],
                        "highlights": ([[asdict(span), kind] for span, kind in service.highlights(text)]
                            if len(text.encode("utf-8")) <= MAX_AUTOMATIC_BYTES else [])})
                elif self.path == "/api/complete":
                    items = service.complete(text, offset, explicit=bool(data.get("explicit")))
                    help = service.signature_help(text, offset)
                    hover = service.hover(text, max(0, offset - 1))
                    self.respond({"items": [asdict(c) for c in items], "signature": asdict(help) if help else None,
                        "hover": asdict(hover) if hover else None})
                elif self.path == "/api/format":
                    self.respond({"text": formatter.format(text, compile_options=service.compiler.options)})
                elif self.path == "/api/snippet":
                    self.respond(asdict(expand_snippet(data["snippet"])))
                elif self.path == "/api/docs":
                    self.respond(service.catalog.search_docs(data.get("query", ""), 3))
                else:
                    self.respond({"error": "Not found"}, 404)
            except (FormatBusy, FormatTimeout, SourceTooLarge) as exc:
                status = 429 if isinstance(exc, FormatBusy) else 504 if isinstance(exc, FormatTimeout) else 413
                self.respond({"error": str(exc)}, status)
            except (ValueError, KeyError, TypeError) as exc:
                diagnostics = [asdict(d) for d in exc.diagnostics] if isinstance(exc, FormatError) else []
                self.respond({"error": str(exc), "diagnostics": diagnostics}, 400)

    return ThreadingHTTPServer((host, port), Handler)


def serve(port=8765, host="0.0.0.0"):
    server = create_server(port, host=host)
    print(f"YARA-X editor playground listening on {host}:{server.server_port}", flush=True)
    if host == "0.0.0.0":
        print(f"Open http://<server-IP>:{server.server_port} from your browser.", flush=True)
    else:
        print(f"Open http://{host}:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
