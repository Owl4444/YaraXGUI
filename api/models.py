"""Pydantic models for the YaraXGUI REST API."""

from __future__ import annotations

from pydantic import BaseModel, Field


# ── Request models ───────────────────────────────────────────────

class CompileRequest(BaseModel):
    rule_text: str = Field(..., max_length=1048576, description="YARA rule source code")


class FormatRequest(BaseModel):
    rule_text: str = Field(..., max_length=1048576, description="YARA rule source code to format")


class ValidateRequest(BaseModel):
    rule_text: str = Field(..., max_length=1048576, description="YARA rule source code to validate")


class ScanRequest(BaseModel):
    rule_text: str = Field(..., max_length=1048576, description="YARA rule source code")
    paths: list[str] = Field(..., min_length=1, max_length=100, description="Server-side file/directory paths to scan")
    recursive: bool = Field(True, description="Recurse into subdirectories")
    exclusions: list[str] = Field(
        default_factory=list, max_length=100,
        description="Glob patterns to exclude (e.g. '*.log', 'temp/')")


class FileInfoRequest(BaseModel):
    path: str = Field(..., max_length=4096, description="Absolute path to file on server")


class FileReadRequest(BaseModel):
    path: str = Field(..., max_length=4096, description="Absolute path to file on server")
    offset: int = Field(0, ge=0, description="Byte offset to start reading")
    length: int = Field(256, ge=1, le=1048576,
                        description="Number of bytes to read (max 1MB)")


class TransformStep(BaseModel):
    name: str = Field(..., description="Transform name from /transforms list")
    params: dict = Field(default_factory=dict, description="Transform parameters")


class TransformRequest(BaseModel):
    data_base64: str = Field(..., max_length=2 * 1024 * 1024, description="Input bytes as base64")
    steps: list[TransformStep] = Field(..., min_length=1, max_length=32,
                                       description="Transform steps to apply in order")


class PatternRequest(BaseModel):
    data_base64: str = Field(..., max_length=87384, description="Input bytes as base64")
    format: str = Field("hex", description="Output format: hex | ascii | regex")
    offset: int = Field(0, ge=0, description="Base offset for comments")


# ── Response models ──────────────────────────────────────────────

class CompileResponse(BaseModel):
    success: bool
    rules_count: int = 0
    message: str = ""
    error: str | None = None


class FormatResponse(BaseModel):
    success: bool
    formatted: str = ""
    error: str | None = None


class ValidateResponse(BaseModel):
    valid: bool
    message: str = ""
    rules_count: int = 0
    rules_info: list[dict] = Field(default_factory=list)
    error: str | None = None


class ScanJobResponse(BaseModel):
    job_id: str
    status: str  # queued | running | completed | failed | cancelled
    message: str = ""


class ScanStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: dict = Field(default_factory=dict)
    created_at: str = ""
    completed_at: str | None = None


class MatchInfo(BaseModel):
    offset: int
    length: int
    hex_dump: str = ""
    data_preview: str = ""
    snippet_b64: str = ""


class PatternInfo(BaseModel):
    identifier: str
    matches: list[MatchInfo] = Field(default_factory=list)


class RuleMatch(BaseModel):
    identifier: str
    namespace: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    patterns: list[PatternInfo] = Field(default_factory=list)


class FileHit(BaseModel):
    filename: str
    filepath: str
    file_size: int
    md5: str
    sha1: str
    sha256: str
    mwdb_sha256: str = ""
    matched_rules: list[RuleMatch] = Field(default_factory=list)


class FileMiss(BaseModel):
    filename: str
    filepath: str
    file_size: int
    md5: str
    sha1: str
    sha256: str


class ScanResultsResponse(BaseModel):
    job_id: str
    status: str
    hits: list[FileHit] = Field(default_factory=list)
    misses: list[FileMiss] = Field(default_factory=list)
    stats: dict = Field(default_factory=dict)
    error_messages: list[str] = Field(default_factory=list)


class FileInfoResponse(BaseModel):
    filename: str
    filepath: str
    file_size: int
    file_type: str
    md5: str
    sha1: str
    sha256: str
    modified: str
    created: str


class FileReadResponse(BaseModel):
    data_base64: str
    offset: int
    length: int
    file_size: int


class TransformInfo(BaseModel):
    name: str
    category: str
    length_preserving: bool
    help: str = ""
    params: list[dict] = Field(default_factory=list)


class TransformResponse(BaseModel):
    success: bool
    data_base64: str = ""
    output_size: int = 0
    debug_log: list[str] = Field(default_factory=list)
    error: str | None = None


class PatternResponse(BaseModel):
    pattern: str
    format: str
