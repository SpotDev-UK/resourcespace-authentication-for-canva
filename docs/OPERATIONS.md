# Platform Operations

Day-two reference: environment matrix, OAuth wiring, signature verification
notes, common failure modes, and a release checklist. For deployment
procedures see [Deployment Runbook](./DEPLOYMENT-RUNBOOK.md); for the
quick-start version see [Deployment Cheatsheet](./DEPLOYMENT-CHEATSHEET.md).

## Environment Matrix

`development`

- `APP_ENV=development` — startup validator skipped
- `RESOURCE_SPACE_MODE=fixture`
- Local OAuth popup against seeded tenants
- Local file-backed JSON store
- Request verification mode typically `smart`
- Manual OAuth helper (`/oauth/manual/callback`) is registered

`staging` / `production`

- `APP_ENV=production` — startup validator enforced
- `RESOURCE_SPACE_MODE=live`
- `CANVA_REQUEST_VERIFICATION_MODE=required`
- `OAUTH_REDIRECT_URI_ALLOWLIST` populated with the exact redirect URIs
  Canva uses
- `CORS_ORIGIN` set to the Canva app origin (no wildcard)
- Dedicated persistent storage path or mounted volume
- Manual OAuth helper returns `404`

## Required Environment Variables

The full list lives in [`.env.example`](../.env.example). The startup
validator (`validate_config_for_environment`) refuses to boot the broker
outside `development` / `test` until each of the following is set to a
non-default value:

- `APP_ENV`
- `BASE_URL`
- `OAUTH_ISSUER`
- `OAUTH_CLIENT_ID`
- `OAUTH_REDIRECT_URI_ALLOWLIST`
- `ASSET_SIGNING_SECRET`
- `STORAGE_PATH`
- `CORS_ORIGIN`
- `CANVA_CLIENT_SECRET`
- `CANVA_REQUEST_VERIFICATION_MODE` (must equal `required`)
- `RESOURCE_SPACE_MODE`
- `RESOURCE_SPACE_ALLOWED_HOSTS`

Tunables and recommended optionals (timestamps, rate limits, upload caps,
metrics token) are documented in `.env.example`.

## OAuth Setup

Configure the Canva OAuth provider to use:

- Authorisation endpoint: `<broker-base-url>/oauth/authorise`
- Token endpoint: `<broker-base-url>/oauth/token`
- Revocation endpoint: `<broker-base-url>/oauth/revoke`
- Userinfo endpoint: `<broker-base-url>/oauth/userinfo`

The OAuth popup is intentionally outside the Canva iframe. Users supply:

- The ResourceSpace base URL
- Username
- Password

The broker validates the tenant URL against `RESOURCE_SPACE_ALLOWED_HOSTS`,
authenticates against that ResourceSpace instance, then returns an
authorisation code to Canva.

OAuth defaults the broker enforces:

- `client_id` must match `OAUTH_CLIENT_ID`
- `redirect_uri` must appear verbatim in `OAUTH_REDIRECT_URI_ALLOWLIST`
  (production)
- PKCE method must be `S256`; `plain` is rejected
- Refresh tokens rotate on every use, with a configurable grace window
  (`OAUTH_REFRESH_GRACE_SECONDS`, default `30`)

## Signature Verification

The broker verifies Canva-signed requests on the webhook endpoint
(`/webhooks/canva/user-uninstall`) when `CANVA_REQUEST_VERIFICATION_MODE`
is `required`. Webhooks are server-to-server calls from Canva, so they
arrive with the `X-Canva-Signatures` and `X-Canva-Timestamp` headers.

The `/content/*` endpoints are **not** signature-verified — they are
called as browser-direct fetches from the Canva app origin and Canva
cannot sign browser-originated traffic. The security boundary on those
endpoints is bearer-token auth (PKCE-S256 OAuth), scope enforcement
(`dam:read` / `dam:write`), the `CORS_ORIGIN` lock, and per-IP rate
limits.

To wire it up:

1. Copy the client secret from the Canva Developer Portal verification page
2. Store the base64 value in `CANVA_CLIENT_SECRET`
3. Set `CANVA_REQUEST_VERIFICATION_MODE=required` for any non-development
   environment

Verification covers:

- Canva-signed GET requests via `signatures` / `time` / `user` / `brand` /
  `extensions` / `state` query parameters
- Canva-signed POST requests via `X-Canva-Signatures` and
  `X-Canva-Timestamp` headers
- Timestamp rejection outside `CANVA_REQUEST_TIMESTAMP_TOLERANCE_SECONDS`
  (default 5 minutes)

## Upload Hardening

Uploads accept a Canva-supplied `source_url` and fetch the bytes
server-side. The broker enforces:

- `https://` only
- Per-redirect-hop host validation
- Optional exact-match host allowlist via `CANVA_UPLOAD_ALLOWED_HOSTS`
- Refusal of any URL whose host resolves to a private, loopback,
  link-local, reserved, or multicast IP
- Streamed download with a `CANVA_UPLOAD_MAX_BYTES` cap (default 50 MiB)
- Pillow `MAX_IMAGE_PIXELS` cap (default 50,000,000) for decompression-bomb
  defence

## Failure Modes

- `INVALID_TENANT_URL`: malformed tenant URL entered in the OAuth popup
- `UNKNOWN_TENANT`: tenant host not in `RESOURCE_SPACE_ALLOWED_HOSTS`
- `INVALID_CREDENTIALS`: ResourceSpace login failed
- `INVALID_CLIENT`: presented `client_id` does not match `OAUTH_CLIENT_ID`
- `INVALID_REDIRECT_URI`: `redirect_uri` not in `OAUTH_REDIRECT_URI_ALLOWLIST`
- `INSUFFICIENT_SCOPE`: token is missing `dam:read` (find/download) or
  `dam:write` (upload)
- `SESSION_EXPIRED`: local OAuth access token expired or was revoked
- `UNSUPPORTED_FORMAT`: asset exists but the MIME type is not supported
- `UPSTREAM_UNAVAILABLE`: ResourceSpace instance not reachable
- `INVALID_CANVA_SIGNATURE`: signed Canva request failed verification

## Release Checklist

- Set `RESOURCE_SPACE_MODE=live`
- Populate `RESOURCE_SPACE_ALLOWED_HOSTS`
- Populate `RESOURCE_SPACE_TENANTS_JSON` if curated container roots are
  required
- Set `CANVA_CLIENT_SECRET`, `OAUTH_CLIENT_ID`,
  `OAUTH_REDIRECT_URI_ALLOWLIST`, `CORS_ORIGIN`
- Verify `/healthz`, `/readyz`, `/metrics`
- Run `pytest`
- Verify the OAuth popup against your ResourceSpace tenant
- Verify `POST /content/resources/find` against real content
- Verify a single design upload from Canva places the resource and a
  preview into the chosen folder
- Verify preview and download grants expire correctly
- Verify the uninstall webhook revokes local sessions
