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
- `STORAGE_ENCRYPTION_KEY` — Fernet key for encrypting sensitive store
  fields (ResourceSpace session keys, user email). Generate with
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
  Required outside development/test.
- `CORS_ORIGIN`
- `CANVA_CLIENT_SECRET`
- `CANVA_REQUEST_VERIFICATION_MODE` — must be `required`
- `RESOURCE_SPACE_MODE`

Leave `RESOURCE_SPACE_ALLOWED_HOSTS` empty so customers can enter the
ResourceSpace URL they normally use, including custom domains and
self-hosted instances. Set it only to lock the broker to known hostname
suffixes. Use `RESOURCE_SPACE_TENANTS_JSON` only for per-tenant overrides
such as an explicit `apiUrl`. Dynamically entered tenants remain restricted
to HTTPS without embedded credentials, public DNS, and a same-origin API URL.
Non-default HTTPS ports are preserved.

**Tunables (defaults usually fine)**

- `PORT`
- `TOKEN_TTL_SECONDS`
- `SIGNED_URL_TTL_SECONDS`
- `AUTH_CODE_TTL_SECONDS`
- `OAUTH_REFRESH_GRACE_SECONDS`
- `REFRESH_TOKEN_TTL_SECONDS`: refresh-token lifetime, default `2592000`
  (30 days); a shorter value is prudent for UAT
- `STORE_PRUNE_INTERVAL_SECONDS`: background prune interval for expired
  store records, in seconds; default `3600` (`0` disables)
- `CANVA_REQUEST_TIMESTAMP_TOLERANCE_SECONDS`
- `CANVA_UPLOAD_ALLOWED_HOSTS`
- `CANVA_UPLOAD_MAX_BYTES`
- `CANVA_UPLOAD_MAX_IMAGE_PIXELS`
- `OAUTH_CLIENTS_JSON`
- `RATE_LIMIT_MAX_REQUESTS`
- `RATE_LIMIT_WINDOW_MS`
- `CLIENT_IP_HEADER`: header carrying the original client IP for rate limits
  and SSO per-source quotas; defaults to `x-real-ip` outside development/test.
  Honoured only when the transport peer matches `TRUSTED_PROXY_HOSTS`.
- `TRUSTED_PROXY_HOSTS`: comma-separated CIDRs/addresses of reverse proxies
  permitted to set `CLIENT_IP_HEADER` (defaults to RFC1918+loopback+`100.64.0.0/10`
  outside development/test). Required when `CLIENT_IP_HEADER` is configured.
- `CLIENT_IP_LOG_KEY`: optional HMAC key for `transportPeerHash` /
  `resolvedClientHostHash` (defaults to `ASSET_SIGNING_SECRET`).
- `CLIENT_IP_LOG_DIAGNOSTICS`: when `true`, SSO identity logs also include raw
  `transportPeer` for proxy tuning. Permitted only when `APP_ENV` is
  `development`, `test`, `staging`, or `uat`.
- `RESOURCE_SPACE_SSO_ENABLED`: enables the ResourceSpace hosted-login
  (SSO) handoff; default `false` (disabled)
- `RESOURCE_SPACE_SSO_SYSTEM_KEY`: ResourceSpace `system` destination key
  for the handoff URL; default `canva`
- `RESOURCE_SPACE_SSO_PENDING_TTL_SECONDS`: pending handoff-state validity
  in seconds; default `600`
- `RESOURCE_SPACE_SSO_REPLAY_RETENTION_SECONDS`: tombstone retention for a
  used/expired handoff state, in seconds; default `600`
- `RESOURCE_SPACE_ASSET_ALLOWED_HOSTS`: optional egress allowlist for the
  signed-asset proxy fetch; empty allows any public host
- `RESOURCE_SPACE_ASSET_PROXY_MAX_BYTES`: cap on a proxied asset response;
  default `52428800` (50 MiB)
- `METRICS_TOKEN`

See [`.env.example`](../.env.example) for the full annotated list.

## ResourceSpace SSO redirect patch (deployment dependency)

Dan's ResourceSpace patch makes the hosted-login consent flow issue **HTTP 303**
to the broker's `redirectUrl` after a successful `POST /oauth/sso/callback`, so
the Canva OAuth popup completes without manual navigation. The broker callback
response is unchanged (HTTP 200 JSON with `redirectUrl`).

- Confirm the patch is applied on each tenant before enabling
  `RESOURCE_SPACE_SSO_ENABLED=true`.
- **Re-check after every ResourceSpace upgrade** — upstream changes can remove
  or alter the redirect behaviour.
- Complete live browser UAT (see [UAT validation](./UAT-VALIDATION.md)) proving
  the popup follows the 303, preserves Canva `state`, and exchanges the code.
  The consent form uses `CentralSpacePost`; verify the PHP `Location` response
  navigates the popup rather than being consumed only inside an async request.

## Railway client IP verification (SSO enablement prerequisite)

Before setting `RESOURCE_SPACE_SSO_ENABLED=true`, confirm per-client rate
limiting works on the deployed platform:

1. Deploy with defaults (`CLIENT_IP_HEADER=x-real-ip`,
   `TRUSTED_PROXY_HOSTS` including RFC1918+loopback+`100.64.0.0/10`). Startup
   logs `platform_server_starting` with `trustedProxyHosts` and
   `uvicornProxyHeaders: false`.
2. Run two SSO handoffs from **distinct end-user networks** (e.g. home vs mobile
   hotspot, or two colleagues on different ISPs). This exercises
   `POST /oauth/authorise` with `auth_method=sso` (browser-initiated).
3. Inspect `oauth_sso_initiated` logs. Each event includes hashed identifiers
   (not raw IPs) plus trust diagnostics:
   - `transportPeerHash` — hash of the direct TCP peer (Railway edge/proxy)
   - `resolvedClientHostHash` — hash of the address used for rate-limit/SSO
     quota keys on initiation
   - `clientIpHeaderTrusted` — must be `true` on Railway when proxy trust is
     configured correctly
4. **Pass criteria (initiation only):** `resolvedClientHostHash` differs between
   the two end-user clients, `clientIpHeaderTrusted` is `true`, and
   `clientIpHeaderPresent` is `true`. If trust fails (`clientIpHeaderPresent`
   true but `clientIpHeaderTrusted` false), obtain the raw transport peer using
   one of:
   - set `CLIENT_IP_LOG_DIAGNOSTICS=true` with `APP_ENV=staging` or `uat` (logs raw
     `transportPeer` on SSO events; rejected for all other environments), then
     disable after tuning; or
   - inspect Railway ingress/proxy connection logs for the upstream TCP source
     address of requests to the service.
   Add that peer/CIDR to `TRUSTED_PROXY_HOSTS` and redeploy before enabling SSO.
   If all initiations collapse to the same hash with trust already true, proxy
   tuning is not the issue — investigate ingress rate-limit collapse instead.
5. Inspect `oauth_sso_callback_received` after a successful handoff. ResourceSpace
   calls this endpoint **server-side**, so callbacks from different users share
   the ResourceSpace server address. Verify `clientIpHeaderTrusted` is `true` and
   `resolvedClientHostHash` is stable across callbacks from the same tenant
   (expected ResourceSpace source), not distinct per end-user network.

Railway overwrites `X-Real-IP` and does not publish fixed proxy addresses;
defaults include CGNAT (`100.64.0.0/10`) for this reason. If the observed
peer falls outside the defaults, set `TRUSTED_PROXY_HOSTS` explicitly.

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
2. **Store compatibility:** releases from this branch onward write Fernet-sealed
   `enc:v1:` session fields. Rolling back to an earlier broker that predates
   field encryption **requires** either restoring a pre-upgrade storage
   snapshot or deleting the store file and having users re-authenticate.
   Keeping the same volume without one of those steps leaves existing sessions
   unusable (the older broker treats ciphertext as a literal session key).
   To rotate `STORAGE_ENCRYPTION_KEY` on the current release, generate a new
   Fernet key, delete the store file, restart, and have users re-authenticate.
3. Reapply the prior environment variables and Canva Developer Portal
   endpoint values if the rollback spans a URL change.
4. Re-run the operational checks above.
5. Confirm the Canva app still completes connect, browse, import, upload,
   and disconnect/reconnect against your ResourceSpace tenant.
