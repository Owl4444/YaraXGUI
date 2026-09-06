# API security audit and deployment

Audited on 2026-09-06. Scope: the headless API, registered repository/MWDB routes,
desktop network clients and credential storage, and server deployment files.
This is a source review with regression and adversarial tests, not an independent
penetration test or a guarantee against unknown vulnerabilities.

## Findings and changes

| Severity | Previous problem | Implemented protection |
| --- | --- | --- |
| Critical when exposed without a key | An unset key silently allowed anonymous reads, repository changes, uploads and scans. | Public mode refuses to start without a non-placeholder key of at least 32 characters. Anonymous development requires an explicit flag and loopback clients/bind address. |
| High | HTTP exposed API keys, MWDB tokens, rules and samples in transit. One MWDB archive-upload path explicitly disabled certificate verification. | HTTPS is the desktop default; TLS verifies chain and hostname. Optional additional CA for the YaraXGUI API. All MWDB client paths require verified HTTPS. No credential-bearing redirects or HTTP fallback. |
| High | Path validation used a string prefix, so an allowed `samples` directory also permitted `samples-secret`. Empty roots meant unrestricted access. Recursive scans followed unchecked files. | Component-based containment, uploads-only access when roots are empty, per-file validation, POSIX descriptor-relative opening, symlink-swap protection, regular files only. Database/configuration files and database sidecars are protected, including hard links. |
| High | YARA `include` could read files outside the sample roots while compiling, validating or formatting. | Includes are disabled at every remote language/scan boundary. Desktop editor includes retain their local behavior. |
| High | Upload dependencies parsed multipart bodies before checking the API key. Chunked bodies, aggregate storage and request counts lacked effective bounds. | Authentication precedes body reads/parsing. Actual bytes, declared length, body deadlines, concurrent requests, upload count and disk quota are checked. Failed uploads are removed. |
| High | Compilation, transforms and scans could block the event loop, exhaust memory or continue after cancellation. | Disposable processes for language work, transforms, import parsing and scans; shared capacity, deadlines, OS memory ceilings and output caps. Cancellation terminates scan workers. File hashing uses bounded chunks off the event loop. |
| High | MWDB jobs accepted arbitrary outbound destinations and redirects, allowing requests into server-accessible networks. Downloads and hashes were unchecked. | Server-configured fixed HTTPS MWDB API URL, exact destination match, redirects disabled, SHA-256 validation, bounded pages/files/results. Blank configuration disables server-side MWDB scanning. |
| High | Automatic MWDB downloads used remote filenames as local paths and could overwrite existing files. Archive upload used a predictable shared temporary filename. | Sanitized, unique automatic download filenames created exclusively; bounded downloads; unique temporary archives with guaranteed cleanup. User-selected save destinations retain the save dialog's overwrite decision. |
| Medium | Credentials fell back to plaintext settings, and MWDB tab saves bypassed the keyring. | New credentials use the OS keyring, or memory for the current session if unavailable. Successful saves clear legacy plaintext fields. Legacy credentials remain readable for migration; save them once through Settings to migrate/clear them. |
| Medium | Wildcard CORS, forwarded-header ambiguity, public configuration details and unbounded repository pagination increased exposure. | Explicit browser origins, exact allowed hosts, explicit proxy trust, minimal health output, private/disabled production documentation, bounded pagination/imports/database storage, and validation errors that do not echo credentials. |
| Medium | The container exposed HTTP publicly and mixed samples with its database. | Public Caddy HTTPS entrypoint; no published API port; separate sample directory; non-root, read-only API container, dropped capabilities, resource limits and bounded logs. |

`api/security.py` owns request policy; `api/paths.py` owns filesystem access;
`api/workers.py` and `api/jobs.py` own resource limits and cancellation;
`yaraxgui/network.py` owns desktop TLS and redirect policy. Plugin routes share
the outer security middleware, so route dependencies cannot accidentally omit it.
The old unbounded scan manager/network implementation has been removed; its
compatibility constructor now returns the secured manager.

## Public deployment with automatic HTTPS

The root `compose.yaml` assumes a DNS name and Caddy on the same host. Caddy
obtains and renews public certificates when the domain points to the server and
ports 80/443 are reachable. Its certificate data must remain persistent.
See [Caddy's automatic HTTPS documentation](https://caddyserver.com/docs/automatic-https).

1. Back up the existing database/data directory. Copy `.env.example` to `.env`
   only if you do not already have one; otherwise merge the new variables.
2. Generate a new key with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
   Set `YARAXGUI_API_KEY` and `YARAXGUI_DOMAIN` in `.env`. Rotate any key previously
   used over HTTP. Keep `.env` private (`chmod 600 .env` on Unix).
   `YARAXGUI_DOMAIN` is the site hostname clients connect to, without scheme or
   port, such as `yara.example.com`; replace the example with your own hostname.
   Do not set it to `0.0.0.0` or `::`. Those are listen addresses, whereas Caddy
   uses this value to select the site's certificate and match requests. Docker's
   published ports already listen on all host interfaces by default.
3. Set `YARAXGUI_DATA_DIR` to your existing data directory. The default remains
   `/mnt/exthdd/yaraxgui-data`; `rules.db` stays at its root. Create `samples/`
   and `uploads/` beneath it, writable by UID/GID 1000 where necessary. Put
   scan inputs in `samples/`; do not put credentials or databases there.
4. Point the domain's A/AAAA records at the server. Permit inbound TCP 80/443;
   remove any old port-forward/firewall rule for 7777 or 8000. Do not add an API
   `ports:` mapping. The private subnet `172.30.77.0/29` must not conflict with
   your networks; if changed, update Compose, Caddy's upstream and proxy trust together.
5. Validate and launch: `docker compose config --quiet`, then
   `docker compose up -d --build`. Check `docker compose ps` and
   `docker compose logs --tail=100 caddy yaraxgui-api`.
6. In desktop **Settings → Connections**, set `https://your-domain`, enable
   **Require HTTPS**, and enter the API key. Leave the CA field empty for a
   public certificate. Changing the checkbox does not provision a server certificate. Reconnect an
   existing repository tab after changing the server URL in Settings.

Caddy's HTTP listener is for certificate validation and HTTPS redirects.
Clients must start with an HTTPS URL: redirecting an HTTP request cannot undo
credentials already transmitted without encryption. The internal Caddy-to-API
hop is HTTP on a private same-host Docker network. For a proxy on another host,
use TLS on that upstream hop too, or a separately secured tunnel.

The stack trusts forwarded headers only from Caddy's fixed private address.
Caddy uses its default handling of forwarded headers; do not add a blanket
`trusted_proxies` setting or `header_up X-Forwarded-Proto {header...}` rule.
See [Caddy reverse proxy headers](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
and [Uvicorn proxy settings](https://www.uvicorn.org/settings/).

## LAN HTTPS by IP address (no domain needed)

Use the updated project files on the server, including `deployment/Caddyfile`
with its `default_sni` setting. Run the following steps in PowerShell from the
project folder (for example, `R:\Tools\YaraXGUI\YaraXGUI`). Docker Desktop must
be running with Linux containers.

1. Run `ipconfig` and find the IPv4 address of the active Ethernet/Wi-Fi adapter
   that your desktop can reach. Use the server's LAN address, not a Docker/WSL
   adapter address or `0.0.0.0`. The examples below use `192.168.1.50`; replace
   it everywhere with your actual address.
2. Edit the project's `.env` file and set `YARAXGUI_DOMAIN=192.168.1.50`.
   Despite the variable name, a domain is not required. Keep your existing API
   key and data settings. For a new installation only, copy `.env.example` to
   `.env` and generate a key with
   `py -3.13 -c "import secrets; print(secrets.token_urlsafe(32))"`, then set
   `YARAXGUI_API_KEY` to that value. Never overwrite an existing `.env` with the
   example file.
3. Clear any PowerShell domain override, recreate the services and check their
   status:

   ```powershell
   Remove-Item Env:YARAXGUI_DOMAIN -ErrorAction SilentlyContinue
   .\scripts\compose.bat up -d --build --force-recreate
   .\scripts\compose.bat ps
   ```

   Wait for `yaraxgui-api` to be healthy and Caddy to be running. If startup
   fails, run `.\scripts\compose.bat logs --tail=80 yaraxgui-api caddy`.
4. Export Caddy's public CA certificate:

   ```powershell
   .\scripts\compose.bat cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
   ```

5. Copy `caddy-root.crt` to the computer running YaraXGUI through a trusted
   channel and keep it at a stable path. In **Settings → Editor Settings…**,
   under Connections, set the server URL to `https://192.168.1.50`, keep
   **Require HTTPS** enabled, select this file in **Additional CA (PEM)**, and
   enter the same API key as the server's `YARAXGUI_API_KEY`. Save the settings.
6. In **Rule Repository**, select **Remote Server**, enter the same
   `https://192.168.1.50` URL and click **Connect**. Use port 443 (implicit in
   this URL); port 7777 is internal to Docker.

If startup still reports a listen address in allowed hosts, inspect just that
setting without printing your API key:

```powershell
$config = .\scripts\compose.bat config --format json | ConvertFrom-Json
$config.services.'yaraxgui-api'.environment.YARAXGUI_ALLOWED_HOSTS
```

It should show your LAN IP followed by `127.0.0.1`, for example
`192.168.1.50,127.0.0.1`. Correct any custom Compose override still supplying
`0.0.0.0` or `::` and recreate the services.

On Linux, use `ip -4 addr` to find the LAN address, `unset YARAXGUI_DOMAIN` to
clear a shell override, and `./scripts/compose.sh` for the Compose commands.
Reserve the address in DHCP or update the server configuration and desktop URL
if it changes.
No public DNS or hosts-file entry is needed. Permit LAN access to TCP 443 in
the server firewall; public Internet port forwarding is unnecessary for LAN use.

Caddy automatically issues private-IP certificates using its local CA. Its root
certificate is PEM even though the file ends in `.crt`. The Caddyfile's
`default_sni` selects the configured site's certificate for IP clients, which
omit the TLS server-name extension. This matters through Docker port forwarding:
Caddy sees its container address, which differs from the IP in the certificate.
Certificate/IP verification and HTTP Host validation remain enabled.
See [Caddy default_sni](https://caddyserver.com/docs/caddyfile/options#default_sni).

Keep the `caddy-data` volume to preserve the CA, and never export its private key.
Trust inside the container does not establish trust on the desktop computer.
For a later public deployment, configure your real DNS name and follow the
public deployment instructions above.

## Rule Repository connection failures

If Caddy logs show `domains:["0.0.0.0"]` or warn about an unspecified IP,
correct `YARAXGUI_DOMAIN` in `.env` and recreate both services with
`scripts\compose.bat up -d --build` (Windows) or
`./scripts/compose.sh up -d --build` (Linux). A plain restart does not apply
changed environment variables. Update the desktop URL to the same hostname.

Alternatively, for LAN HTTPS with a local hostname, use a name such as
`YARAXGUI_DOMAIN=yara.local` and connect to `https://yara.local`. Configure local
DNS or each desktop's hosts file to resolve that name to the server's actual LAN
IP (for example, `192.168.1.50 yara.local`). On Windows the hosts file is
`C:\Windows\System32\drivers\etc\hosts` and requires administrator access to edit;
on Linux it is `/etc/hosts`. Use the hostname in the URL, including on the server
computer itself. This also lets the TLS client identify the intended site when
Docker forwards the connection into a different network address.

Caddy uses a local CA for `.local` names; each desktop needs to trust that CA.
Once Caddy is running, export its public root certificate:

```powershell
.\scripts\compose.bat cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

On Linux, replace `.\scripts\compose.bat` with `./scripts/compose.sh`. Transfer
this certificate through a trusted channel and select it in the desktop's
Additional CA (PEM) setting (the file is PEM despite its `.crt` extension).
Caddy's log saying its root is trusted refers to the container's trust store;
it does not install trust on the Windows host or remote desktops. Keep the
`caddy-data` volume persistent to preserve the CA. Never transfer its private key.

For this Compose deployment, enter `https://your-domain` in Settings and the
repository's Server field, then reconnect. Port 443 is the public HTTPS entry
point; 7777 is private to Docker. Enabling Require HTTPS changes the URL scheme
but deliberately preserves custom ports for installations using direct TLS.
An old `http://host:7777` URL therefore needs to be updated for Compose.

The repository displays copyable, wrapped diagnostics for DNS, refused/reset
connections, timeouts and TLS failures. Check the indicated cause:

- **Cannot resolve:** verify DNS for the configured hostname and any proxy.
- **Connection refused / timed out:** check the containers, published port 443,
  firewall and proxy. From the project folder on Windows run
  `scripts\compose.bat ps` and
  `scripts\compose.bat logs --tail=100 caddy yaraxgui-api`. On Linux use
  `./scripts/compose.sh` with the same arguments. Resolve any API startup error
  such as an unwritable data directory before reconnecting.
- **Certificate verification:** use the hostname covered by the certificate,
  check its validity dates/system clock and the server's certificate chain.
  For a private CA, obtain its CA certificate from your administrator and select
  it in Additional CA (PEM) on the desktop computer. Do not select a private key
  or disable verification. Publicly trusted certificates normally need no extra CA.
- **TLS negotiation:** confirm the target port actually serves HTTPS.
- **TLSV1_ALERT_INTERNAL_ERROR:** the TLS endpoint aborted the handshake before
  API authentication. With Compose, check Caddy logs for certificate issuance
  failures and use the hostname configured in `YARAXGUI_DOMAIN`, rather than a
  different hostname or IP address. For example, a site configured for
  `yara.example.com` should be accessed as `https://yara.example.com`.
  Public certificate issuance also depends on correct public DNS and reachable
  validation ports (see [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https)).
  The error alone does not identify the server's underlying failure; it does
  not mean the client must enable obsolete TLS 1.0 or disable verification.
- **HTTP 401/403:** check the API key in Settings and the server's access policy;
  this is an HTTP response, distinct from a transport connection failure.

If unresolved, copy the full connection error and server URL for diagnosis.
Never include API keys, private keys or `.env` contents.

## Switching between Linux and Windows

Use the platform launcher from the project folder. It chooses the Compose files
explicitly, so there is no need to create or replace `compose.override.yaml`.

Windows PowerShell or cmd:

```powershell
.\scripts\compose.bat up -d --build
.\scripts\compose.bat logs --tail=100 yaraxgui-api caddy
.\scripts\compose.bat ps
```

Linux:

```sh
./scripts/compose.sh up -d --build
./scripts/compose.sh logs --tail=100 yaraxgui-api caddy
./scripts/compose.sh ps
```

The Windows launcher selects `compose.yaml` plus
`deployment/compose.windows.yaml` (a Docker-managed data volume). The Linux
launcher selects `compose.yaml` (the existing `YARAXGUI_DATA_DIR` bind mount).
The shell launcher also recognizes Windows Git Bash/MSYS/Cygwin. WSL is a Linux
shell and selects Linux storage; to use the Windows volume from WSL, select
both files explicitly with `docker compose -f compose.yaml -f
deployment/compose.windows.yaml ...`.

These launchers forward Compose commands/arguments and return Docker's exit code.
They work from another directory too. An existing `compose.override.yaml` or
`COMPOSE_FILE` setting is not loaded by these explicit-file commands. If you
have other local customizations, add them explicitly, for example
`./scripts/compose.sh -f compose.local.yaml up -d --build`. Ordinary
`docker compose` still follows its own file-discovery rules; it does not select
an override according to the host operating system.

Keep `.env` local to each machine. Changing platforms does not copy/synchronize
server databases or uploads between Docker engines or between the Linux bind
mount and the Windows volume. Continue using the same launcher and project name
on each machine to retain its data.

## Windows / Docker Desktop storage

For consistent database backups, readable YARA exports and migration between
Windows and Linux, use the [repository transfer guide](REPOSITORY_BACKUPS.md).

Use Docker Desktop in **Linux containers** mode. The base Compose file preserves
an existing Linux bind-mount default (`/mnt/exthdd/yaraxgui-data`). That is not a
Windows folder. A bind mount also replaces the image's `/data` directory and its
permissions, which can cause `PermissionError: '/data/uploads'` for UID 1000.
See [Docker's bind-mount behavior](https://docs.docker.com/engine/storage/bind-mounts/).

For a new Windows deployment, use `scripts/compose.bat` as shown above.
Alternatively, for a Windows-only checkout where you prefer plain
`docker compose`, copy the storage override from PowerShell in the repository root:

```powershell
Copy-Item .\deployment\compose.windows.yaml .\compose.override.yaml
docker compose config --quiet
docker compose up -d --build
docker compose logs --tail=100 yaraxgui-api caddy
```

If you already have `compose.override.yaml`, merge the template's volume settings
into it instead of replacing your existing customization. Compose automatically
loads this local override. It replaces only the API's `/data` mount with the
`yaraxgui-data` named volume; the API remains UID/GID 1000 with a read-only image.
A fresh volume is populated from the image's prepared data directory. Docker
stores the database, uploads and samples outside the Git checkout, and retains
them when containers are recreated. See [Docker volumes](https://docs.docker.com/engine/storage/volumes/).

Keep the same Compose project/directory name to reuse the volume. Avoid
`docker compose down -v` or removing that volume unless you intend to delete
its data. The Windows override does not use `YARAXGUI_DATA_DIR`. Existing data in
a bind-mounted folder stays there and is **not automatically copied** to the new
volume. For an existing database, keep the bind mount as described below or
migrate a stopped/SQLite-backed-up database before switching storage.

If you want ordinary Windows folders, use the base Compose file without the
named-volume override, set this in `.env`, and create the folders first:

```dotenv
YARAXGUI_DATA_DIR=./server-data
```

```powershell
New-Item -ItemType Directory -Force .\server-data\uploads, .\server-data\samples
docker compose up -d --build
```

You can also use an existing local path such as `C:/YaraXGUI/server-data`, with
forward slashes. The Windows account running Docker Desktop needs write access
to the selected directory; allow its sharing in Docker Desktop if required.
The database belongs at `server-data/rules.db`, beside `uploads/` and `samples/`.
Do not fix a storage permission error by running the public API as root.

`.gitignore` and `.dockerignore` exclude local Compose overrides, `.env` variants,
`server-data/`, `data/`, `uploads/` and certificate/private-key storage. The shared
`.env.example` and `deployment/compose.windows.yaml` remain versioned. Ignore
rules do not untrack files that were already committed.

## Existing proxy or certificate files

For an HTTPS reverse proxy running natively on the same host, run the API with:

```sh
export YARAXGUI_API_KEY='<generated-key>'
export YARAXGUI_ALLOWED_HOSTS='yara.example.com,127.0.0.1'
export YARAXGUI_HOST='127.0.0.1'
export YARAXGUI_TRUSTED_PROXIES='127.0.0.1'
export YARAXGUI_ALLOWED_ROOTS='/srv/yaraxgui/samples'
export YARAXGUI_REPO_DB='/srv/yaraxgui/rules.db'
export YARAXGUI_UPLOAD_DIR='/srv/yaraxgui/uploads'
python -m api.server
```

The proxy must preserve the public Host, overwrite forwarded headers using the
actual client connection, and forward to `127.0.0.1:7777`. Set header/body/idle
limits comparable to `deployment/Caddyfile`. Never use `*` or `0.0.0.0/0` for
trusted proxies. A different host/container needs its actual source IP and
firewall isolation; trusting a proxy does not itself restrict network access.
Use one API process: job state, quotas and rate limits are process-local.

For direct HTTPS, remove `YARAXGUI_TRUSTED_PROXIES` and set:

```sh
export YARAXGUI_SSL_CERTFILE='/srv/yaraxgui/certs/fullchain.pem'
export YARAXGUI_SSL_KEYFILE='/srv/yaraxgui/certs/privkey.pem'
export YARAXGUI_HOST='0.0.0.0'
python -m api.server
```

Also set the API key, allowed hosts and data paths shown above. The launcher
requires both certificate files and TLS 1.2 or newer. Renew certificates and
restart the service after renewal. Keep private keys outside sample roots and
restrict their filesystem permissions. For a private CA, select its PEM **CA
certificate**, never its private key, in desktop Settings. Certificate errors
must be fixed at the URL/certificate/trust store; verification cannot be disabled.
The Caddy deployment is preferred for an Internet-facing service because it also
handles certificate renewal and front-end connection/header timeouts.

The launcher reads environment variables; it does not source `.env` automatically.
On Windows, set the equivalent variables in PowerShell with `$env:NAME='value'`.
`scripts/run_api.sh` invokes the same launcher and accepts `--host` and `--port`.
Do not replace it with a multi-worker/raw Uvicorn invocation that bypasses its
transport and resource configuration checks.

## Local development

```sh
YARAXGUI_DEV_MODE=1 python -m api.server
```

This binds `127.0.0.1:7777`. In Windows cmd, use `set YARAXGUI_DEV_MODE=1` first.
Use `http://localhost:7777` and disable **Require HTTPS** only for this local
instance. Anonymous development cannot be used through a proxy or accessed from
another computer. Docs are at `/docs`; includes remain disabled for remote API
requests. The standalone `yarax-editor demo` integration preview is a development
tool, not this authenticated API: never expose that preview publicly.

## Limits and settings

All sizes are binary MiB/KiB. Values are deliberately conservative; large corpus
jobs should be split into smaller submissions.

| Setting / resource | Default |
| --- | --- |
| `YARAXGUI_REQUIRE_HTTPS` | `1` in public mode; cannot be disabled there |
| `YARAXGUI_ALLOWED_HOSTS` | Required, comma-separated lowercase names/IPs without ports |
| `YARAXGUI_CORS_ORIGINS` | Empty: no cross-origin browser clients; native clients unaffected |
| `YARAXGUI_ENABLE_DOCS` | `0` in public mode; documentation also requires the key if enabled |
| `YARAXGUI_RATE_LIMIT` | 120 requests/minute per client IP, including failed auth |
| `YARAXGUI_MAX_REQUESTS` | 8 active requests; launcher also caps connections/tasks at 32 |
| `YARAXGUI_BODY_TIMEOUT` | 60 seconds total to receive a body |
| JSON / rule / formatting input | 4 MiB body / 1 MiB UTF-8 rule / 256 KiB UTF-8 formatting |
| `YARAXGUI_MAX_UPLOAD_MB` | 100 MiB per file; multipart overhead also bounded |
| `YARAXGUI_UPLOAD_QUOTA_MB` | 1024 MiB total uploads; at most 1000 files |
| `YARAXGUI_MAX_FILE_MB` | 100 MiB per scan input or hash request |
| `YARAXGUI_MAX_SCAN_FILES` | 1000 local files per scan |
| `YARAXGUI_SCAN_TIMEOUT` | 60 seconds per complete job; configurable up to 600 |
| Worker capacity / memory / default deadline | 2 workers / 512 MiB address-space or commit limit each / 30 seconds |
| Scan history | 16 jobs, at most 2 queued/running; memory only, lost on restart |
| Scan/transform output | 8 MiB budget; worker JSON message at most 16 MiB |
| Transform input / steps | 2 MiB base64 field / 32 steps |
| Pattern generation | Approximately 64 KiB of input |
| Repository pages / imports | At most 250 rows per page and 8 MiB returned; 1000 rules per import |
| `YARAXGUI_REPO_MAX_MB` | 256 MiB SQLite main-file page limit; existing larger databases are not shrunk |
| `YARAXGUI_MWDB_URL` | Empty disables server-side MWDB; otherwise one trusted HTTPS API URL, including `/api` |
| `YARAXGUI_MWDB_CA_FILE` | Optional additional CA PEM on the server for MWDB |

MWDB server scans download sequentially inside the worker rather than spawning
unbounded network work; the legacy `parallel_downloads` field is accepted but
has no effect. Tokens are cleared when jobs finish or are cancelled. Current
results are returned on completion; killing a job discards in-flight results.
For a private MWDB CA, set `YARAXGUI_MWDB_CA_FILE` to a PEM CA bundle before
launching the desktop too. This applies to both its urllib and mwdblib transports;
otherwise their standard trust stores are used. The Settings CA field is
specifically for the YaraXGUI API.

## Remaining boundaries and operational responsibilities

- This is a **shared administrator API**, not a multi-tenant service. Every key
  holder can modify/delete repository rules, list shared jobs/results and manage
  uploads. There are no per-user permissions, scoped keys, tenant separation or
  tamper-evident audit trail. Do not offer this as an anonymous public analysis
  service. Use an identity-aware proxy/VPN and individual access controls if
  multiple people need access; true per-user isolation needs an authorization redesign.
- Worker processes limit resource exhaustion; they are not a sandbox against a
  native-code vulnerability in YARA-X or a decompressor. Keep dependencies/images
  patched. Run on an isolated host/container without unrelated secrets, host
  mounts or Docker socket access. Restrict outbound traffic to the configured
  MWDB service where practical. Trust its DNS and certificate administration.
- Sample directories must be administrator-controlled. Use local storage and
  read-only mounts for external sample collections. POSIX has descriptor-relative
  symlink protection; Windows requires ACL isolation because Python lacks the
  same portable reparse-point/openat protection. Host administrators and processes
  that can modify configuration or mount topology remain trusted.
- Rate/concurrency limits cannot stop distributed traffic exhaustion. Monitor
  rejected requests, disk space, memory and restarts using infrastructure tooling;
  add network-level rate controls appropriate to the hosting environment. The
  unauthenticated health response deliberately reveals only `status: ok`.
- Uploads persist until explicitly deleted; configure retention if appropriate.
  Set a filesystem/container-volume quota as well: temporary multipart copies,
  SQLite WAL files, backups, existing files and operator-added files are outside
  the logical main-file/upload quotas. Database imports can be partially committed
  if storage fills. Back up the database using SQLite-aware backup or stop the API
  while copying it; test restoration.
- HTTPS protects transport, not server-side data at rest. Protect the data directory,
  `.env`, certificate keys and backups with host permissions/encryption as needed.
  Any legacy plaintext desktop credential remains until resaved/migrated; if the OS
  keyring fails, new credentials last only for the current application session.
- API access logging is off by default to avoid logging sensitive queries. Never
  log headers/bodies or enable Caddy `log_credentials`. Add access monitoring with
  explicit redaction if needed. This does not provide forensic per-user auditing.

The HTTPS, authentication and input-limit design follows the
[OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html).

## Verification

Final regression result: **365 passed, 2 skipped**. The skips are the optional Windows-generated XPRESS corpus and native
Windows ntdll tests. Real TLS and security-boundary tests passed.
Compose and Caddy configuration validation passed; the Settings layout was
checked at a 600×680 window size. Container startup/build could not be tested
here because access to the Docker daemon socket is denied.

Run `python -m pytest tests -q` in the desktop development environment.
`tests/test_api_security.py` covers production startup failures, auth before body
reads, duplicate/chunked lengths, slow bodies, rate/capacity limits, proxy spoofing,
path escapes, upload cleanup/quota, repository limits, MWDB destination restrictions,
transform expansion, scan progress, cancellation and worker cleanup.
`tests/test_api_tls.py` exercises a real HTTPS server, custom CA trust, hostname
mismatch, untrusted certificates, rejected redirects and Settings defaults.

Validate deployment with `docker compose config --quiet` and
`caddy validate --config deployment/Caddyfile --adapter caddyfile` after setting
a test/domain environment. Public DNS/certificate issuance and the actual Docker
network/firewall still require verification on the deployment host.

Dependency advisory check: `pip-audit` against the development environment initially
reported advisories for its old `pip` 24.0 installer. After upgrading the installer,
the check reported no known vulnerabilities in 65 audited installed packages.
The local `yarax-editor` package was skipped by the advisory service because it
is not published on PyPI; its API integration is covered by source review/tests.
The Docker build upgrades to `pip>=26.2` before installing server dependencies.
This is a point-in-time package advisory check; it does not audit the base image,
unpublished bugs, or the exact future deployment. Re-run dependency and container
scans after updates and before publishing an image.
