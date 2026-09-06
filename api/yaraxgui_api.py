"""YaraXGUI REST API Server.

Headless FastAPI server exposing all YaraXGUI capabilities:
  - YARA rule compilation, validation, formatting
  - Async file/directory scanning with progress
  - File upload, info & hex reading
  - Data transforms (encoding, crypto, compression)
  - YARA pattern generation

Security policy and deployment instructions: docs/API_SECURITY.md.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
from contextlib import asynccontextmanager
import shutil
import sys
import tempfile
import time as _time
import uuid
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from fastapi import (FastAPI, File, HTTPException, Security, Depends,
                     UploadFile)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse, Response

from api.models import (
    CompileRequest, CompileResponse,
    FormatRequest, FormatResponse,
    ValidateRequest, ValidateResponse,
    ScanRequest, ScanJobResponse, ScanStatusResponse, ScanResultsResponse,
    FileInfoRequest, FileInfoResponse,
    FileReadRequest, FileReadResponse,
    TransformRequest, TransformResponse, TransformInfo,
    PatternRequest, PatternResponse,
)
from api.jobs import SecureScanManager
from api.security import SecurityPolicy, APISecurityMiddleware
from api.paths import configured_file_policy
from api.workers import ProcessRunner, WorkerBusy

from starlette.concurrency import run_in_threadpool

# ── Configuration ────────────────────────────────────────────────

POLICY = SecurityPolicy.from_env()
UPLOAD_DIR = os.environ.get("YARAXGUI_UPLOAD_DIR", os.path.join(tempfile.gettempdir(), "yaraxgui_uploads"))
MAX_UPLOAD_SIZE = POLICY.max_upload_bytes
MAX_RULE_SIZE = 1024 * 1024
FILE_POLICY = configured_file_policy()
_runner = ProcessRunner()
_scan_manager = SecureScanManager(POLICY, _runner)
_upload_lock = asyncio.Lock()

@asynccontextmanager
async def lifespan(app):
    try:
        yield
    finally:
        await _scan_manager.shutdown()

# ── App setup ────────────────────────────────────────────────────

app = FastAPI(
    lifespan=lifespan,
    docs_url="/docs" if POLICY.expose_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if POLICY.expose_docs else None,
    title="YaraXGUI API",
    description="REST API for YARA rule scanning, analysis, and data transforms.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Rules", "description": "YARA rule compilation, validation, formatting"},
        {"name": "Scanning", "description": "Async file/directory scanning"},
        {"name": "MWDB", "description": "Server-to-server MWDB scanning"},
        {"name": "Uploads", "description": "File upload/download for remote scanning"},
        {"name": "Files", "description": "File info, hashing, hex reading"},
        {"name": "Transforms", "description": "Data transforms (encoding, crypto, compression)"},
        {"name": "Patterns", "description": "YARA pattern generation"},
        {"name": "Repository", "description": "YARA rule repository (search, CRUD, import)"},
        {"name": "System", "description": "Health check and server info"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(POLICY.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.exception_handler(RequestValidationError)
async def invalid_request(request, exc):
    # Do not echo submitted credentials or megabytes of invalid input. Escaped
    # ASCII JSON also handles malformed Unicode in diagnostic locations safely.
    errors = [{key: item[key] for key in ('type', 'loc', 'msg') if key in item}
              for item in exc.errors()[:100]]
    return Response(json.dumps({'detail': errors}, ensure_ascii=True),
                    status_code=422, media_type='application/json')


@app.exception_handler(UnicodeError)
async def invalid_unicode(request, exc):
    return JSONResponse({'detail': 'Request contains invalid Unicode'}, status_code=400)


# This outer middleware authenticates before FastAPI parses multipart/JSON.
app.add_middleware(APISecurityMiddleware, policy=POLICY)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(key: str | None = Security(_api_key_header)):
    """Expose the auth scheme in OpenAPI; enforcement lives in middleware."""


def _validate_path(path_str: str) -> Path:
    try:
        return FILE_POLICY.validate(path_str)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (ValueError, OSError):
        raise HTTPException(400, "Invalid path")


def _validate_rule_size(rule_text: str):
    if len(rule_text.encode('utf-8')) > MAX_RULE_SIZE:
        raise HTTPException(413, "Rule text exceeds 1 MiB")


async def _work(operation, payload):
    try:
        return await run_in_threadpool(_runner.run, operation, payload)
    except WorkerBusy as exc:
        raise HTTPException(429, str(exc), headers={"Retry-After": "5"}) from exc
    except TimeoutError as exc:
        raise HTTPException(408, str(exc)) from exc
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(422, str(exc)) from exc


try:
    from hex_editor.transforms import (
        REGISTRY, load_builtin_plugins,
    )
    load_builtin_plugins()
    _transforms_available = True
except Exception:
    _transforms_available = False

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════════════
#  RULES ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.post("/rules/compile", response_model=CompileResponse,
          dependencies=[Depends(verify_api_key)], tags=["Rules"])
async def compile_rules(req: CompileRequest):
    """Compile YARA rules and return success/error."""
    _validate_rule_size(req.rule_text)
    return CompileResponse(**await _work('compile', {'text': req.rule_text}))


@app.post("/rules/format", response_model=FormatResponse,
          dependencies=[Depends(verify_api_key)], tags=["Rules"])
async def format_rules(req: FormatRequest):
    """Format YARA source code."""
    _validate_rule_size(req.rule_text)
    try:
        return FormatResponse(success=True, formatted=await _work('format', {'text': req.rule_text}))
    except HTTPException as exc:
        if exc.status_code != 422:
            raise
        return FormatResponse(success=False, error=str(exc.detail))


@app.post("/rules/validate", response_model=ValidateResponse,
          dependencies=[Depends(verify_api_key)], tags=["Rules"])
async def validate_rules(req: ValidateRequest):
    """Validate YARA rule syntax and return structure info."""
    _validate_rule_size(req.rule_text)
    return ValidateResponse(**await _work('validate', {'text': req.rule_text}))


# ══════════════════════════════════════════════════════════════════
#  FILE UPLOAD ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.post("/upload", dependencies=[Depends(verify_api_key)], tags=["Uploads"])
async def upload_file(file: UploadFile = File(...)):
    """Upload a file to the server for scanning.

    Returns a server-side path that can be used with /scan, /file/info, etc.
    Files are stored in a temp directory and should be cleaned up after use.
    """
    if file.size and file.size > MAX_UPLOAD_SIZE:
        raise HTTPException(
            413, f"File too large ({file.size} bytes, max {MAX_UPLOAD_SIZE})")

    upload_id = uuid.uuid4().hex[:12]
    upload_subdir = Path(UPLOAD_DIR) / upload_id
    # Always choose a server filename: prevents Windows device names, alternate
    # streams, path separators, and executable control characters on all hosts.
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", (file.filename or "upload").replace("\\", "/").split("/")[-1])[:160]
    safe_name = "sample_" + (safe_name.strip(". ") or "upload")
    dest = upload_subdir / safe_name
    total = 0
    async with _upload_lock:
        used, count = await run_in_threadpool(_upload_usage)
        if count >= 1000:
            raise HTTPException(413, "Upload count limit reached; delete old uploads")
        upload_subdir.mkdir(parents=True, exist_ok=False, mode=0o700)
        try:
            with dest.open("xb") as output:
                while chunk := await file.read(65536):
                    total += len(chunk)
                    if total > MAX_UPLOAD_SIZE or used + total > POLICY.upload_quota_bytes:
                        raise HTTPException(413, "Upload size or storage quota exceeded")
                    await run_in_threadpool(output.write, chunk)
        except BaseException:
            shutil.rmtree(upload_subdir, ignore_errors=True)
            raise
        finally:
            await file.close()

    return {
        "upload_id": upload_id,
        "filename": safe_name,
        "path": str(dest),
        "size": total,
        "message": "Upload successful. Use this path with /scan or /file/info. "
                   "Call DELETE /upload/{upload_id} when done.",
    }


def _upload_usage():
    files = [p for directory in Path(UPLOAD_DIR).iterdir()
             if directory.is_dir() and not directory.is_symlink()
             for p in directory.iterdir() if p.is_file() and not p.is_symlink()]
    return sum(p.stat().st_size for p in files), len(files)


@app.delete("/upload/{upload_id}", dependencies=[Depends(verify_api_key)], tags=["Uploads"])
def delete_upload(upload_id: str):
    """Delete an uploaded file and its directory."""
    # Validate upload_id is a safe hex string (prevent traversal)
    if not re.fullmatch(r"[0-9a-f]{12}", upload_id):
        raise HTTPException(400, "Invalid upload ID")

    upload_subdir = Path(UPLOAD_DIR) / upload_id
    if upload_subdir.is_symlink() or not upload_subdir.is_dir():
        raise HTTPException(404, "Upload not found")

    shutil.rmtree(upload_subdir, ignore_errors=True)
    return {"upload_id": upload_id, "message": "Deleted"}


@app.get("/uploads", dependencies=[Depends(verify_api_key)], tags=["Uploads"])
def list_uploads():
    """List all uploaded files."""
    result = []
    upload_root = Path(UPLOAD_DIR)
    if upload_root.exists():
        for subdir in upload_root.iterdir():
            if subdir.is_dir() and not subdir.is_symlink():
                files = list(subdir.iterdir())
                for f in files:
                    if f.is_file() and not f.is_symlink():
                        result.append({
                            "upload_id": subdir.name,
                            "filename": f.name,
                            "path": str(f),
                            "size": f.stat().st_size,
                        })
    return result


# ══════════════════════════════════════════════════════════════════
#  SCANNING ENDPOINTS (async jobs)
# ══════════════════════════════════════════════════════════════════

@app.post("/scan", response_model=ScanJobResponse,
          dependencies=[Depends(verify_api_key)], tags=["Scanning"])
async def start_scan(req: ScanRequest):
    """Submit a scan job. Returns immediately with a job ID."""
    _validate_rule_size(req.rule_text)
    for p in req.paths:
        vp = _validate_path(p)
        if not vp.exists():
            raise HTTPException(404, f"Path not found: {p}")

    try:
        job = _scan_manager.create_job(req.rule_text, req.paths, req.recursive, req.exclusions)
    except WorkerBusy as exc:
        raise HTTPException(429, str(exc)) from exc
    _scan_manager.submit(job)
    return ScanJobResponse(job_id=job.job_id, status=job.status,
                           message="Scan job created")


@app.get("/scan/{job_id}", response_model=ScanStatusResponse,
         dependencies=[Depends(verify_api_key)], tags=["Scanning"])
async def get_scan_status(job_id: str):
    """Get the status and progress of a scan job."""
    job = _scan_manager.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return ScanStatusResponse(**job.to_status_dict())


@app.get("/scan/{job_id}/results", response_model=ScanResultsResponse,
         dependencies=[Depends(verify_api_key)], tags=["Scanning"])
async def get_scan_results(job_id: str):
    """Get the full results of a completed scan job."""
    job = _scan_manager.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status not in ("completed", "failed", "cancelled"):
        raise HTTPException(409, f"Job is still {job.status}")
    return ScanResultsResponse(**job.to_results_dict())


@app.delete("/scan/{job_id}", dependencies=[Depends(verify_api_key)], tags=["Scanning"])
async def cancel_scan(job_id: str):
    """Cancel a running scan job."""
    job = _scan_manager.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    job.cancel()
    return {"job_id": job_id, "message": "Cancel requested"}


@app.get("/scans", dependencies=[Depends(verify_api_key)], tags=["Scanning"])
async def list_scans():
    """List all scan jobs."""
    return _scan_manager.list_jobs()


# ══════════════════════════════════════════════════════════════════
#  FILE ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.post("/file/info", response_model=FileInfoResponse,
          dependencies=[Depends(verify_api_key)], tags=["Files"])
def file_info(req: FileInfoRequest):
    """Get file hashes, size, type, and timestamps."""
    p = _validate_path(req.path)
    if not p.exists():
        raise HTTPException(404, "File not found")
    if not p.is_file():
        raise HTTPException(400, "Path is not a file")

    digests = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
    maximum = int(os.environ.get('YARAXGUI_MAX_FILE_MB', '100')) * 1024**2
    try:
        with FILE_POLICY.open(p) as stream:
            stat = os.fstat(stream.fileno())
            if stat.st_size > maximum:
                raise HTTPException(413, 'File exceeds configured size limit')
            data = stream.read(4)
            for digest in digests:
                digest.update(data)
            size = len(data)
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > maximum:
                    raise HTTPException(413, 'File exceeds configured size limit')
                for digest in digests:
                    digest.update(chunk)
    except (PermissionError, OSError, ValueError) as exc:
        raise HTTPException(403, 'File access denied') from exc

    magic = data[:4] if len(data) >= 4 else data
    if magic[:2] == b'MZ':
        ftype = "PE"
    elif magic[:4] == b'\x7fELF':
        ftype = "ELF"
    elif magic[:4] in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                        b'\xcf\xfa\xed\xfe'):
        ftype = "Mach-O"
    elif magic[:3] == b'PK\x03':
        ftype = "ZIP"
    elif magic[:2] == b'\x1f\x8b':
        ftype = "Gzip"
    elif magic[:4] == b'Rar!':
        ftype = "RAR"
    elif magic[:4] == b'\x89PNG':
        ftype = "PNG"
    elif magic[:3] == b'\xff\xd8\xff':
        ftype = "JPEG"
    elif magic[:4] == b'%PDF':
        ftype = "PDF"
    else:
        ftype = "Unknown"

    return FileInfoResponse(
        filename=p.name,
        filepath=str(p),
        file_size=stat.st_size,
        file_type=ftype,
        md5=digests[0].hexdigest(),
        sha1=digests[1].hexdigest(),
        sha256=digests[2].hexdigest(),
        modified=_time.strftime("%Y-%m-%d %H:%M:%S",
                                _time.localtime(stat.st_mtime)),
        created=_time.strftime("%Y-%m-%d %H:%M:%S",
                               _time.localtime(stat.st_ctime)),
    )


@app.post("/file/read", response_model=FileReadResponse,
          dependencies=[Depends(verify_api_key)], tags=["Files"])
def file_read(req: FileReadRequest):
    """Read bytes from a file at a given offset (for hex view)."""
    p = _validate_path(req.path)
    if not p.exists():
        raise HTTPException(404, "File not found")
    if not p.is_file():
        raise HTTPException(400, "Path is not a file")

    try:
        with FILE_POLICY.open(p) as f:
            file_size = os.fstat(f.fileno()).st_size
            f.seek(req.offset)
            data = f.read(req.length)
    except (PermissionError, OSError, ValueError) as exc:
        raise HTTPException(403, 'File access denied') from exc

    return FileReadResponse(
        data_base64=base64.b64encode(data).decode("ascii"),
        offset=req.offset,
        length=len(data),
        file_size=file_size,
    )


# ══════════════════════════════════════════════════════════════════
#  TRANSFORM ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.get("/transforms", response_model=list[TransformInfo],
         dependencies=[Depends(verify_api_key)], tags=["Transforms"])
async def list_transforms():
    """List all available data transforms."""
    if not _transforms_available:
        return []
    result = []
    for spec in REGISTRY:
        params = []
        for p in (spec.params or []):
            params.append({
                "key": p.key, "label": p.label, "kind": p.kind,
                "default": p.default, "choices": p.choices,
                "placeholder": p.placeholder, "help": p.help,
            })
        result.append(TransformInfo(
            name=spec.name, category=spec.category,
            length_preserving=spec.length_preserving,
            help=spec.help, params=params,
        ))
    return result


@app.post("/transform/apply", response_model=TransformResponse,
          dependencies=[Depends(verify_api_key)], tags=["Transforms"])
async def apply_transform(req: TransformRequest):
    """Apply a transform recipe to base64-encoded bytes."""
    if not _transforms_available:
        raise HTTPException(501, "Transforms not available")

    try:
        return TransformResponse(**await _work('transform', req.model_dump()))
    except HTTPException as exc:
        if exc.status_code != 422:
            raise
        return TransformResponse(success=False, error=str(exc.detail))


# ══════════════════════════════════════════════════════════════════
#  PATTERN GENERATION
# ══════════════════════════════════════════════════════════════════

@app.post("/patterns/generate", response_model=PatternResponse,
          dependencies=[Depends(verify_api_key)], tags=["Patterns"])
def generate_pattern(req: PatternRequest):
    """Generate a YARA pattern string from bytes."""
    try:
        data = base64.b64decode(req.data_base64, validate=True)
    except Exception:
        raise HTTPException(400, "Invalid base64 input")

    fmt = req.format.lower()
    offset = req.offset

    if fmt == "hex":
        hex_str = " ".join(f"{b:02X}" for b in data)
        pattern = (f"$hex = {{ {hex_str} }}"
                   f"  // 0x{offset:08X}, {len(data)} bytes")
    elif fmt == "ascii":
        text = ""
        for b in data:
            if b == 0x00: text += "\\0"
            elif b == 0x09: text += "\\t"
            elif b == 0x0A: text += "\\n"
            elif b == 0x0D: text += "\\r"
            elif b == 0x22: text += '\\"'
            elif b == 0x5C: text += "\\\\"
            elif 0x20 <= b < 0x7F: text += chr(b)
            else: text += f"\\x{b:02x}"
        pattern = (f'$str = "{text}" ascii'
                   f"  // 0x{offset:08X}, {len(data)} bytes")
    elif fmt == "regex":
        _META = set(r"/\.^$*+?{}[]|()")
        text = ""
        for b in data:
            ch = chr(b) if 0x20 <= b < 0x7F else ""
            if ch and ch in _META: text += "\\" + ch
            elif ch: text += ch
            elif b == 0x09: text += "\\t"
            elif b == 0x0A: text += "\\n"
            elif b == 0x0D: text += "\\r"
            else: text += f"\\x{b:02x}"
        pattern = (f"$re = /{text}/"
                   f"  // 0x{offset:08X}, {len(data)} bytes")
    else:
        raise HTTPException(400, f"Unknown format: {fmt}. Use hex|ascii|regex")

    return PatternResponse(pattern=pattern, format=fmt)


# ══════════════════════════════════════════════════════════════════
#  PLUGIN LOADER — dynamically register plugin API endpoints
# ══════════════════════════════════════════════════════════════════

from plugins.base import load_plugins, PLUGIN_REGISTRY

_plugins_dir = Path(getattr(sys, '_MEIPASS',
                            Path(__file__).parent.parent)) / "plugins"
load_plugins(_plugins_dir)

# Share the scan manager with plugins that need it
try:
    from plugins import mwdb_retrohunt
    mwdb_retrohunt.set_scan_manager(_scan_manager)
except (ImportError, AttributeError):
    pass

# Register all plugin API routes
# Static paths first, then parameterized (to avoid FastAPI route conflicts)
_static_routes = []
_param_routes = []
for _pname, _pspec in PLUGIN_REGISTRY.items():
    for _route in _pspec.api_routes:
        if '{' in _route.path:
            _param_routes.append((_pname, _route))
        else:
            _static_routes.append((_pname, _route))

for _pname, _route in _static_routes + _param_routes:
    try:
        app.add_api_route(
            _route.path,
            _route.handler,
            methods=[_route.method],
            tags=_route.tags,
            dependencies=[Depends(verify_api_key)],
            response_model=_route.response_model,
        )
    except Exception as e:
        print(f"[plugin] {_pname}: failed to register {_route.method} "
              f"{_route.path}: {e}", file=sys.stderr)

_loaded_plugin_names = list(PLUGIN_REGISTRY.keys())


# ══════════════════════════════════════════════════════════════════
#  HEALTH
# ══════════════════════════════════════════════════════════════════

@app.get("/health", tags=["System"])
async def health():
    """Health check (no auth required)."""
    return {"status": "ok"}


# ── Entry point ──────────────────────────────────────────────────

if __name__ == "__main__":
    from api.server import main
    main()
