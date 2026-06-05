# Deployment Runbook

Detailed reference for deploying, upgrading, and rolling back the broker.
For a one-page quick start see the
[Deployment Cheatsheet](./DEPLOYMENT-CHEATSHEET.md). For day-two operations
see [Operations](./OPERATIONS.md).

## Runtime

- Python `3.11+` with FastAPI / Uvicorn (single process)
- HTTPS base URL for every non-local environment
- Persistent writable storage for `STORAGE_PATH`
- Secrets injected at deploy time, never committed to source control

## Start Command

Local:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
python -m resourcespace_platform.main
```

Container:

```bash
docker build -f deploy/Dockerfile -t resourcespace-platform:latest .
docker run --env-file /etc/resourcespace-platform/broker.env \
  -v /var/lib/resourcespace-platform:/var/lib/resourcespace-platform \
  -p 3001:3001 resourcespace-platform:latest
```

The image installs from `requirements.lock`, so builds are reproducible.
Regenerate the lockfile with `uv pip compile pyproject.toml -o requirements.lock`
after bumping deps in `pyproject.toml`.

Systemd: install the package into `/opt/resourcespace-platform/.venv`,
place secrets in `/etc/resourcespace-platform/broker.env`, and enable
`deploy/resourcespace-platform.service`.

The broker listens on `PORT` and serves the OAuth provider endpoints, the
Canva DAM broker endpoints, and the grant/webhook endpoints from the same
process.

## Required Environment Variables

The startup validator refuses to boot the broker outside `development` /
`test` until every required variable below is set to a non-default value.

**Required in production**

- `APP_ENV` — `production` or `staging`
- `BASE_URL`
- `OAUTH_ISSUER`
- `OAUTH_CLIENT_ID`
- `OAUTH_REDIRECT_URI_ALLOWLIST`
- `ASSET_SIGNING_SECRET`
- `STORAGE_PATH`
- `CORS_ORIGIN`
- `CANVA_CLIENT_SECRET`
- `CANVA_REQUEST_VERIFICATION_MODE` — must be `required`
- `RESOURCE_SPACE_MODE`
- `RESOURCE_SPACE_ALLOWED_HOSTS`

**Tunables (defaults usually fine)**

- `PORT`
- `TOKEN_TTL_SECONDS`
- `SIGNED_URL_TTL_SECONDS`
- `AUTH_CODE_TTL_SECONDS`
- `OAUTH_REFRESH_GRACE_SECONDS`
- `CANVA_REQUEST_TIMESTAMP_TOLERANCE_SECONDS`
- `CANVA_UPLOAD_ALLOWED_HOSTS`
- `CANVA_UPLOAD_MAX_BYTES`
- `CANVA_UPLOAD_MAX_IMAGE_PIXELS`
- `OAUTH_CLIENTS_JSON`
- `RATE_LIMIT_MAX_REQUESTS`
- `RATE_LIMIT_WINDOW_MS`
- `RESOURCE_SPACE_TENANTS_JSON`
- `METRICS_TOKEN`

See [`.env.example`](../.env.example) for the full annotated list.

## Operational Checks

Run after every deploy and after any rollback:

1. `GET /healthz` returns `200 {"ok": true}`
2. `GET /readyz` returns `200 {"ok": true}`
3. `GET /metrics` returns aggregate counts (or extended payload with
   `METRICS_TOKEN`)
4. `GET /oauth/authorise` from the Canva app loads the OAuth popup
5. One end-to-end OAuth flow against your ResourceSpace tenant succeeds
6. `POST /content/resources/find` returns live tenant content
7. `POST /content/resources/{id}/download-url` returns expiring signed URLs
8. `POST /webhooks/canva/user-uninstall` revokes local OAuth sessions

## Rollback

1. Redeploy the previous release tag for this repo.
2. Keep the same persistent `STORAGE_PATH` volume unless the rollback
   specifically requires restoring a storage snapshot.
3. Reapply the prior environment variables and Canva Developer Portal
   endpoint values if the rollback spans a URL change.
4. Re-run the operational checks above.
5. Confirm the Canva app still completes connect, browse, import, upload,
   and disconnect/reconnect against your ResourceSpace tenant.
