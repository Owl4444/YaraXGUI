import argparse
from dataclasses import asdict
from importlib.resources import files
import json
from pathlib import Path
import sys
from .compiler import Compiler, CompileOptions
from .formatter import format_source, FormatError
from .service import LanguageService


def main(argv=None):
    parser = argparse.ArgumentParser(description="Standalone YARA-X editor toolkit")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "format", "complete"):
        command = sub.add_parser(name)
        command.add_argument("file", help="UTF-8 source file, or - for stdin")
        command.add_argument("--include-dir", action="append", default=[])
        command.add_argument("--globals", default="{}", help="JSON external globals")
        if name == "complete":
            command.add_argument("--offset", required=True, type=int, help="Python character offset")
    docs = sub.add_parser("docs")
    docs.add_argument("query")
    sub.add_parser("info")
    demo = sub.add_parser("demo")
    demo.add_argument("--host", default="0.0.0.0", help="IPv4 bind address (default: all interfaces)")
    demo.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if args.command == "demo":
        from .playground import serve
        serve(args.port, host=args.host)
        return 0
    if args.command == "info":
        compiler = Compiler()
        print(json.dumps({"engine": compiler.version, "modules": compiler.modules,
            "reference": str(files("yarax_editor").joinpath("data/reference"))}, indent=2))
        return 0
    if args.command == "docs":
        from .catalog import Catalog
        for hit in Catalog().search_docs(args.query, 3):
            print(hit["path"] + "\n" + hit["markdown"])
        return 0
    try:
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8")
        compiler = Compiler(CompileOptions(globals=json.loads(args.globals), include_dirs=tuple(args.include_dir),
            allow_includes=bool(args.include_dir), origin=None if args.file == "-" else args.file))
        if args.command == "check":
            result = compiler.validate(text)
            print(json.dumps({"valid": result.valid, "diagnostics": [asdict(d) for d in result.diagnostics]}, indent=2))
            return 0 if result.valid else 1
        if args.command == "format":
            sys.stdout.write(format_source(text, compiler=compiler))
        else:
            print(json.dumps([asdict(c) for c in LanguageService(compiler).complete(text, args.offset, explicit=True)], indent=2))
        return 0
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print(str(exc), file=sys.stderr)
        if isinstance(exc, FormatError):
            for diagnostic in exc.diagnostics:
                print(diagnostic.message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
