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

- `client_id` must match the primary `OAUTH_CLIENT_ID` or a configured entry
  in `OAUTH_CLIENTS_JSON`
- `redirect_uri` must appear verbatim in the allowlist for that exact OAuth
  client: `OAUTH_REDIRECT_URI_ALLOWLIST` for the primary Canva client, or the
  client's `redirectUriAllowlist` in `OAUTH_CLIENTS_JSON`
- PKCE method must be `S256`; `plain` is rejected
- Refresh tokens rotate on every use, with a configurable grace window
  (`OAUTH_REFRESH_GRACE_SECONDS`, default `30`)

`OAUTH_CLIENTS_JSON` is optional and should be left unset for the current
Canva-only deployment. It exists so the broker can later support additional
ResourceSpace-facing integrations without changing the auth/session labelling
code. Example:

```json
[
  {
    "clientId": "tagquest-client",
    "integration": "tagquest",
    "redirectUriAllowlist": ["https://tagquest.example/callback"]
  }
]
```

## ResourceSpace Login POST Hardening

The live ResourceSpace login/session-key exchange uses HTTP POST form data,
not a GET query string. The broker sends the login request to the tenant's
configured `apiUrl` with this form body:

```text
function=login
username=<ResourceSpace username>
password=<ResourceSpace password>
```

This keeps the username and password out of the ResourceSpace login URL, so
they are not captured by normal URL logs, reverse proxy request URI logs, or
browser/network tooling that records request targets. ResourceSpace's API
supports API calls via GET or POST, and `login` still returns the same
session API key used for subsequent signed requests.

Scope of the change:

- Only the unauthenticated ResourceSpace `login` call moved from GET query
  parameters to POST form data.
- The Canva-facing OAuth flow is unchanged: Canva still talks to the broker
  through `/oauth/authorise`, `/oauth/token`, and `/oauth/revoke`.
- Subsequent signed ResourceSpace API calls still use the existing
  session-key signing path. Their query strings contain signed API
  parameters, but not the user's ResourceSpace password.
- Multipart upload calls remain POST requests with signed API parameters
  and file data.

Security and logging expectations:

- Keep all broker-to-ResourceSpace traffic on HTTPS.
- Do not log POST bodies, ResourceSpace passwords, session API keys, OAuth
  access tokens, refresh tokens, or signed asset grant URLs.
- ResourceSpace access logs should show the login request path as the API
  endpoint only, without `username=` or `password=` query parameters.
- Invalid credentials should continue to surface as `INVALID_CREDENTIALS`
  without including the supplied password in logs or error messages.

Operational checks:

- Connect a valid ResourceSpace user through Canva and confirm the broker
  receives a normal OAuth session.
- Review ResourceSpace/API gateway logs for that login attempt and confirm
  the request URL does not contain the username or password.
- Attempt login with invalid credentials and confirm the user-facing failure
  remains the existing invalid-credentials behaviour.
- After a successful login, browse, preview/download, upload, and
  disconnect/reconnect to confirm the existing session-key flow still works.

## ResourceSpace Canva User-Agent Marker

Outbound live ResourceSpace traffic that belongs to a broker-verified Canva
OAuth session carries a ResourceSpace Canva marker in the HTTP `User-Agent`
header:

```text
User-Agent: python-httpx RSCanva
```

The marker is derived by the broker after it validates the OAuth `client_id`
against its server-side OAuth client registry. The primary `OAUTH_CLIENT_ID`
defaults to the Canva integration; future clients can be mapped explicitly via
`OAUTH_CLIENTS_JSON`. The Canva app does not send a trusted marker directly,
and the broker must not blindly forward any frontend-supplied header as proof
of origin. Token records, refresh records, sessions, and short-lived asset
grants are stamped with broker-owned integration metadata so ResourceSpace-bound
requests can be labelled only when they came from a trusted Canva broker
session.

The marker is an operational/audit signal that distinguishes expected Canva
integration traffic from generic `python-httpx` traffic. It is not an
authentication mechanism and it is not proof, on its own, that a request
should be allowed.

The marker is applied to these broker-to-ResourceSpace paths:

- ResourceSpace login/session-key POST calls made through
  `_post_jsonish_sync`.
- ResourceSpace API GET calls made through `_fetch_jsonish_sync`, including
  `get_user_collections`, `search_get_previews`, `get_resource_data`, and
  `get_resource_path`.
- ResourceSpace multipart API uploads made through
  `_post_multipart_live_api`, including the original uploaded file and the
  generated preview upload.
- Proxy fetches for short-lived preview/download grants when the grant
  source is a live ResourceSpace asset URL.

The marker is not applied to ResourceSpace-bound calls that lack the trusted
Canva integration metadata. This keeps the broker safe to extend for other
future integrations without mislabelling their ResourceSpace API traffic as
Canva traffic.

The marker is intentionally **not** applied to Canva export URL downloads in
`_download_bytes`, because those URLs are supplied by Canva during the
upload flow and are not ResourceSpace API traffic.

Keep tenant allowlisting, OAuth bearer-token checks, ResourceSpace permission
checks, CORS controls, rate limits, and request signing in place. Treat the
marker as a routing/auditing signal only. Do not log full signed
ResourceSpace URLs, session keys, download grants, OAuth tokens, or POST
bodies when validating this behaviour.

Operational checks:

- Confirm ResourceSpace/API access logs show `RSCanva` on browse/search,
  preview/download, and upload requests triggered from the Canva app.
- Confirm the marker is absent for ResourceSpace-bound calls made from any
  non-Canva broker integration or any test session without trusted Canva
  metadata.
- If ResourceSpace access rules use this marker as a routing hint, pair it
  with tenant allowlisting and the existing broker/OAuth controls. Keep a
  rollback path ready for the first production rollout.

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
- `INVALID_CLIENT`: presented `client_id` is not in the broker's configured
  OAuth client registry
- `INVALID_REDIRECT_URI`: `redirect_uri` is not in the allowlist for that
  exact OAuth client
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
- Leave `OAUTH_CLIENTS_JSON` unset unless the broker is intentionally serving
  additional integrations; if set, verify each client's redirect allowlist is
  client-specific
- Verify `/healthz`, `/readyz`, `/metrics`
- Run `pytest`
- Verify the OAuth popup against your ResourceSpace tenant
- Verify ResourceSpace logs for the login/session-key request do not include
  `username=` or `password=` in the request URL
- Verify `POST /content/resources/find` against real content
- Verify ResourceSpace logs show `RSCanva` in the user-agent for live
  ResourceSpace requests triggered by browse/search, preview/download, and
  upload flows
- Verify a single design upload from Canva places the resource and a
  preview into the chosen folder
- Verify preview and download grants expire correctly
- Verify the uninstall webhook revokes local sessions
