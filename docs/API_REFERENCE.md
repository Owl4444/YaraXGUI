# REST API reference

Use this catalog to find an endpoint. For setup, see the
[cheatsheet](CHEATSHEET.md) or [HTTPS deployment guide](API_SECURITY.md).

Requests require `X-API-Key` except the minimal `/health` endpoint. Use the HTTPS
URL configured for your server. Remote file paths refer to server-side files
and must be inside its allowed directories; upload a client file first if needed.
A shared API key grants administrator access; there are no per-user roles.

For interactive request/response schemas during loopback development, use a
Python 3.13+ environment. Run
`YARAXGUI_DEV_MODE=1 python -m api.server` on Linux and open
`http://localhost:7777/docs`. In PowerShell, set `$env:YARAXGUI_DEV_MODE="1"`
before running `python -m api.server`. Production documentation endpoints are
disabled by default. See [development setup](DEVELOPMENT.md#headless-api).

## System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Minimal status only (no auth) |

## Rules

| Method | Path | Description |
|--------|------|-------------|
| POST | `/rules/compile` | Compile YARA rules |
| POST | `/rules/validate` | Validate syntax, return structure info |
| POST | `/rules/format` | Format YARA source code |

## Scanning

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan` | Submit async scan job (returns job_id) |
| POST | `/scan/mwdb` | Submit MWDB retrohunt job (server-to-server) |
| GET | `/scan/{job_id}` | Poll job status and progress |
| GET | `/scan/{job_id}/results` | Get full results (hits with hex snippets) |
| DELETE | `/scan/{job_id}` | Cancel a running scan |
| GET | `/scans` | List all jobs |

## File Upload

| Method | Path | Description |
|--------|------|-------------|
| POST | `/upload` | Upload file (multipart form data) |
| GET | `/uploads` | List uploaded files |
| DELETE | `/upload/{upload_id}` | Delete uploaded file |

## File Info

| Method | Path | Description |
|--------|------|-------------|
| POST | `/file/info` | Hashes (MD5/SHA1/SHA256), size, type, timestamps |
| POST | `/file/read` | Read bytes at offset (returns base64) |

## Transforms

| Method | Path | Description |
|--------|------|-------------|
| GET | `/transforms` | List all 40+ transforms with parameters |
| POST | `/transform/apply` | Apply transform recipe to base64 bytes |

## Pattern Generation

| Method | Path | Description |
|--------|------|-------------|
| POST | `/patterns/generate` | Generate YARA pattern (hex/ascii/regex) from bytes |

## Rule Repository (plugin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/repo/rules` | Search rules (`?q=`, `?family=`, `?tags=`, `?author=`) |
| POST | `/repo/rules` | Add a rule with metadata |
| POST | `/repo/rules/import` | Bulk import from multi-rule .yar file |
| GET | `/repo/rules/{rule_id}` | Get single rule |
| PUT | `/repo/rules/{rule_id}` | Update rule fields |
| DELETE | `/repo/rules/{rule_id}` | Delete a rule |
| GET | `/repo/stats` | Total rules, families, sources |
| GET | `/repo/families` | List distinct families |
| GET | `/repo/tags` | List distinct tags |

## Workflows

**Local file scanning:**
```
POST /scan {rule_text, paths} → {job_id}
GET  /scan/{job_id}           → poll progress
GET  /scan/{job_id}/results   → hits with hex/ascii snippets
```

**File upload + scan:**
```
POST   /upload (file)         → {upload_id, path}
POST   /scan {rule_text, paths: [path]} → {job_id}
GET    /scan/{job_id}/results → results
DELETE /upload/{upload_id}    → cleanup
```

**MWDB retrohunt (server-to-server):**
```
POST /scan/mwdb {rule_text, mwdb_url, mwdb_token, query, limit} → {job_id}
GET  /scan/{job_id}           → poll progress (scanned/total/matches)
GET  /scan/{job_id}/results   → hits with hex/ascii snippets from server
```

For MWDB scans, the requested URL must match the server's configured
`YARAXGUI_MWDB_URL`. Match snippets are returned in scan results; explicit
sample downloads still transfer files to the client. See the
[request limits and access policy](API_SECURITY.md#limits-and-settings).

Database backup/restore is an administrator CLI operation, not an HTTP endpoint.
Use the [repository transfer guide](REPOSITORY_BACKUPS.md).
