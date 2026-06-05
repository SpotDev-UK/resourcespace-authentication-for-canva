# ResourceSpace Platform Broker

Designed and written by **SpotDev Services Ltd** in partnership with
Montala Limited. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for
copyright and trade-mark terms.

Tenant-aware OAuth and content broker that sits between the Canva app and a
ResourceSpace tenant. Owns:

- hosted-tenant ResourceSpace URL validation in the OAuth popup
- ResourceSpace credential exchange and session binding
- persistent OAuth code/token/grant storage
- template-facing resource discovery, download, and **upload** for the Canva app
- short-lived public preview/download grants
- uninstall handling, request throttling, health endpoints, structured logs

You can find the user interface for this in the Canva app, the source code
for which is in the following repo:

- [`resourcespace-canva-app`](https://github.com/SpotDev-UK/resourcespace-canva-app)

---

## Runtime

- **Python 3.11+** with FastAPI / Uvicorn
- stateless HTTP process with a persistent JSON store on disk
- Pillow for preview-image generation (see "Upload flow" below)
- no compiled build step required

---

## Modes

- `RESOURCE_SPACE_MODE=live` — real ResourceSpace tenant. Uses `login`,
  `get_user_collections`, `search_get_previews`, `get_resource_data`,
  `get_resource_path`, `create_resource`, `upload_multipart`,
  `add_resource_to_collection`, `update_field`.
- `RESOURCE_SPACE_MODE=fixture` — deterministic in-memory tenants/users/collections
  for development and automated tests.

Fixture mode rejects upload calls explicitly — uploads are live-only.

---

## API surface

OAuth:

- `GET /oauth/authorise` (also `GET /oauth/authorize` — redirects to the `-ise` spelling)
- `POST /oauth/authorise` (also `POST /oauth/authorize`)
- `POST /oauth/token`
- `POST /oauth/revoke`
- `GET /oauth/userinfo`
- `GET /oauth/manual/callback` — helper used by the `manual_test=1` query
  flag to exercise the full authorize/token round-trip from a browser without
  the Canva app

Canva-facing session and content:

- `GET /api/session`
- `POST /content/resources/find`
- `POST /content/resources/:id/download-url`
- `POST /content/resources/upload`

Public asset delivery:

- `GET /public/assets/:grantId`
- `GET /signed/assets/:grantId`

Operations:

- `GET /` — JSON service descriptor (env, RS mode, pointer to the endpoints above)
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `POST /webhooks/canva/user-uninstall`

---

## Upload flow

`POST /content/resources/upload` accepts:

```json
{
  "url": "<canva-export-url>",
  "containerId": "collection:<ref>",
  "title": "<optional>"
}
```

The broker then, against the signed-in tenant:

1. `create_resource(resource_type=1, archive=0)` — returns the new `ref`.
2. Downloads the bytes from `url` itself (bypasses ResourceSpace's
   `$api_upload_urls` allow-list).
3. `upload_multipart` with the full file — stores the bytes.
4. Generates a downsized JPEG preview with Pillow and uploads it via
   `upload_multipart previewonly=1`. Uploading our own preview flips
   `has_image` to `1` and sets thumbnail dimensions.
5. `update_field 8` — optional title/filename.
6. `add_resource_to_collection` — link into the selected collection.

Preview generation is best-effort: if Pillow is missing or the source bytes
can't be decoded, the upload still succeeds without a thumbnail.

---

## Local development

```bash
cp .env.example .env
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
python -m resourcespace_platform.main
```

Default local URL: `http://localhost:3001`

Fixture credentials:

- tenant `https://acme.demo.resourcespace.local` — `alice / alice-password`,
  `bob / bob-password`
- tenant `https://globex.demo.resourcespace.local` — `clara / clara-password`

---

## Commands

- `python -m resourcespace_platform.main` — start the broker on `$PORT` (default `3001`)
- `pytest` — run the test suite
- `pip install -e ".[dev]"` — install editable + dev deps

Diagnostic scripts under `scripts/` — each takes credentials as CLI flags
(`--base-url`, `--username`, `--password`) so you can point them at any
tenant without committing secrets:

- `scripts/test_create_resource.py` — verify a ResourceSpace tenant accepts
  API calls and the `create_resource` function.
- `scripts/upload_test.py` — exercise the full create → upload → preview
  pipeline end-to-end against a tenant. Pass `--image /path/to/image.png`.
- `scripts/preview_test.py` — isolate the Pillow preview-generation step
  against an existing resource. Pass `--resource <ref>`.

---

## Deployment

The broker is a standard FastAPI app with no platform lock-in. Railway is
SpotDev's **recommended** host because it covers TLS, log retention, and
one-command deploys with no extra infrastructure work — but the build
artefacts (`deploy/Dockerfile` and a systemd unit) are portable, so you can
run the broker anywhere that satisfies the runtime contract below.

### Runtime contract (any host)

- **Python**: 3.11 or newer (the Dockerfile uses `python:3.11-slim`).
- **Process**: `python -m resourcespace_platform.main`. Listens on the port
  in `PORT` (defaults to `3001`).
- **Environment**: copy `.env.example` and populate the broker secrets
  (Canva client id/secret, signing keys, redirect-uri allowlist, CORS
  origin, ResourceSpace tenant config). Never commit populated `.env`
  files — set them in your host's secret store. The required env vars for
  production are listed in **Required environment in production** below;
  the broker refuses to start if any are missing or unsafe.
- **Persistent storage**: `STORAGE_PATH` must point at a writable path that
  survives restarts. Defaults to
  `/var/lib/resourcespace-platform/platform-store.json`. On container
  hosts, mount a volume there; on VMs, the systemd unit's
  `StateDirectory=resourcespace-platform` handles this.
- **Healthcheck**: `GET /readyz` returns `200` once the JSON store and
  config are loaded. `GET /healthz` is a cheaper liveness probe.
- **Outbound network**: HTTPS to each configured ResourceSpace tenant and
  to Canva's public endpoints. No inbound traffic from anywhere except
  Canva and the configured tenants needs to reach the broker — front it
  with TLS and (optionally) an IP allow-list.
- **Identity**: run as a non-root user. The Dockerfile creates
  `uid 1001 broker`; the systemd unit uses
  `User=resourcespace-platform` plus the standard hardening directives
  (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`).
- **Dependency pinning**: `requirements.lock` (generated with `uv pip
  compile pyproject.toml`) is committed and used by the Dockerfile via
  `pip install -r requirements.lock`. Regenerate after bumping deps in
  `pyproject.toml`.

### Required environment in production

The broker calls `validate_config_for_environment()` at startup. When
`APP_ENV` is anything other than `development` or `test`, it refuses to
boot until **every** value below is provided. The validator prints a
precise list of which variables are missing or unsafe.

| Env var | Why it matters |
| --- | --- |
| `APP_ENV` | Set to `production` (or `staging`) to enable the validator and disable dev-only helpers (notably `/oauth/manual/callback`). |
| `CANVA_CLIENT_SECRET` | Base64-encoded secret from your Canva app. Used to verify the signature on the user-uninstall webhook (Canva → broker, server-to-server). |
| `CANVA_REQUEST_VERIFICATION_MODE=required` | Gates `/webhooks/canva/user-uninstall` only. Default is `smart` (dev convenience). Production must enforce. The `/content/*` endpoints are protected by bearer-token + scope, not signature, because Canva can't sign the browser-direct fetches the DAM panel makes. |
| `ASSET_SIGNING_SECRET` | Long random value (`python -c "import secrets; print(secrets.token_urlsafe(32))"`). The default `development-signing-secret` is rejected. |
| `OAUTH_CLIENT_ID` | The primary OAuth client id Canva uses against this broker. The `canva-dev-app` placeholder is rejected unless you also set `OAUTH_ALLOW_DEFAULT_CLIENT_ID=true` (only safe when the redirect-URI allowlist is tight). |
| `OAUTH_REDIRECT_URI_ALLOWLIST` | Comma-separated, exact-match list of redirect URIs the primary Canva integration uses. The broker rejects any other `redirect_uri` on `/oauth/authorise`. |
| `CORS_ORIGIN` | Comma-separated list of origins Canva uses to talk to the broker. Typically the iframe origin (`https://app-<lowercased-app-id>.canva-apps.com`) AND the editor origin (`https://www.canva.com`) — the editor fetches image bytes when a user drags an asset onto the canvas. Wildcard `*` is rejected. |

Other env vars worth setting (not validated, but recommended):

| Env var | What it does |
| --- | --- |
| `CANVA_UPLOAD_ALLOWED_HOSTS` | Comma-separated host allowlist for the Canva-supplied `source_url` on uploads. Leave empty to allow any public host (private IPs are blocked unconditionally). Capture real hosts from your first deploy's logs and tighten. |
| `CANVA_UPLOAD_MAX_BYTES` | Cap on the size of a downloaded export in bytes. Default `52428800` (50 MiB). |
| `CANVA_UPLOAD_MAX_IMAGE_PIXELS` | Pillow's anti-decompression-bomb limit. Default `50000000`. |
| `OAUTH_CLIENTS_JSON` | Optional JSON array for additional broker clients. Each entry needs `clientId`, optional `integration`, and `redirectUriAllowlist`; the redirect allowlist is enforced per client. Leave unset for the current Canva-only deployment. |
| `OAUTH_REFRESH_GRACE_SECONDS` | How long the just-rotated refresh token remains valid so two near-simultaneous refresh calls don't collide. Default `30`. |
| `METRICS_TOKEN` | When set, `/metrics` returns the extended posture payload only to callers presenting `Authorization: Bearer <this>`. Empty means `/metrics` returns aggregate counts only (no posture data). |

### Discovering the redirect URI and Canva export hosts

Canva does not publish a single canonical `redirect_uri` or export host
that fits every integration — they depend on how your Canva app is
configured. The recommended workflow:

1. Deploy the broker once with `APP_ENV=development` (validator off) and
   permissive defaults.
2. Wire up your Canva app, complete one OAuth flow, and trigger one design
   export.
3. Read the broker's structured logs for the exact `redirect_uri` Canva
   sent on `/oauth/authorise` and the host on the upload `source_url`.
4. Move those values into `OAUTH_REDIRECT_URI_ALLOWLIST` and
   `CANVA_UPLOAD_ALLOWED_HOSTS`, then flip `APP_ENV=production`.

### Railway (recommended)

- **Service**: link the Railway CLI to the intended project, environment, and
  service for your deployment. Keep project IDs, access tokens, and
  environment-specific service names out of version control.
- **Build**: Dockerfile at `deploy/Dockerfile`, declared in `railway.toml`.
  Keep the same Dockerfile path configured in the Railway service manifest.
- **Deploy command**: `railway up --detach` from the repo root. GitHub
  auto-deploy is not enabled on this service.
- **State**: persisted under `/var/lib/resourcespace-platform/platform-store.json` via a Railway volume mount.
- **Healthcheck**: `GET /readyz`.

#### Gotcha: Railway CLI project path

The Railway CLI stores a project→directory mapping in `~/.railway/config.json`.
`railway up` uses that mapping to determine which folder to upload. If the CLI
is linked against an ancestor directory of this repo, the upload tarball will
not contain `deploy/Dockerfile` or `railway.toml` and deploys fail with
`Dockerfile 'deploy/Dockerfile' does not exist`. Fix:

```bash
cd resourcespace-platform
railway unlink
railway link   # select this project, env, and service
```

### Other container hosts (Fly, Cloud Run, ECS, Kubernetes, plain Docker)

Any host that can build and run `deploy/Dockerfile` will work. Wire up:

1. **Build** the image from the repo root using `deploy/Dockerfile`.
2. **Inject env vars** from your host's secret store (the same set as
   `.env.example`).
3. **Mount a persistent volume** at `/var/lib/resourcespace-platform`
   (or set `STORAGE_PATH` to wherever your volume lives).
4. **Expose port `3001`** (or override `PORT` and the platform's port
   mapping to taste).
5. **Configure the healthcheck** to hit `GET /readyz`.
6. **Terminate TLS** at the platform's load balancer or ingress — the
   broker speaks plain HTTP inside its container.

### VM with systemd

For a long-lived VM (your own hardware, EC2, Hetzner, etc.) the repo ships
`deploy/resourcespace-platform.service`. The unit assumes:

- Code checked out under `/opt/resourcespace-platform`.
- A Python virtualenv at `/opt/resourcespace-platform/.venv` with the
  package installed (`pip install .`).
- An env file at `/etc/resourcespace-platform/broker.env` (mode `0640`,
  owned by the service user).
- A dedicated `resourcespace-platform` system user.
- The systemd-managed state dir at `/var/lib/resourcespace-platform`.

Standard install:

```bash
sudo useradd --system --home /opt/resourcespace-platform resourcespace-platform
sudo install -d -o resourcespace-platform -g resourcespace-platform /opt/resourcespace-platform /etc/resourcespace-platform
# clone the repo into /opt/resourcespace-platform, create .venv, pip install .
sudo install -m 0644 deploy/resourcespace-platform.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now resourcespace-platform
```

Front it with nginx, Caddy, or any reverse proxy that terminates TLS and
forwards to `http://127.0.0.1:3001`.

---

## Release docs

- [Operations](./docs/OPERATIONS.md)
- [Deployment runbook](./docs/DEPLOYMENT-RUNBOOK.md)
- [Deployment cheatsheet](./docs/DEPLOYMENT-CHEATSHEET.md)
- [UAT validation template](./docs/UAT-VALIDATION.md)
- [Licence](./LICENSE)
- [Notice (contributor credits)](./NOTICE)

---

## Licence and copyright

- Designed and written by **SpotDev Services Ltd** in partnership with
  Montala Limited. Copyright (c) 2026 SpotDev Services Ltd.
- BSD-3-Clause licence with ResourceSpace trade-mark protection. Full terms
  in [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
- The ResourceSpace name and logo remain trade marks of Montala Limited.
