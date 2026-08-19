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
- Users enter their ResourceSpace URL in the OAuth popup (custom domains
  and self-hosted instances included). Leave `RESOURCE_SPACE_ALLOWED_HOSTS`
  empty unless you deliberately want to lock the broker to known suffixes.
- `CANVA_REQUEST_VERIFICATION_MODE=required`
- `OAUTH_REDIRECT_URI_ALLOWLIST` populated with the exact redirect URIs
  Canva uses
- `CORS_ORIGIN` set to the Canva app origin (no wildcard)
- Dedicated persistent storage path or mounted volume
- Manual OAuth helper returns `404`
- ResourceSpace SSO handoff (`RESOURCE_SPACE_SSO_ENABLED`) left at its
  default of `false` unless the tenant's hosted-login setup has been
  validated.

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

Leave `RESOURCE_SPACE_ALLOWED_HOSTS` empty so any public HTTPS ResourceSpace
URL works (hosted tenants, custom domains, and self-hosted instances). Set
it only if you deliberately want to lock the broker to known hostname
suffixes. Use `RESOURCE_SPACE_TENANTS_JSON` only for per-tenant overrides
such as an explicit `apiUrl`.

Dynamically entered tenant URLs must use HTTPS without embedded credentials,
public DNS, and a same-origin API URL. Non-default HTTPS ports are preserved. Private, loopback, link-local, reserved, multicast,
CGNAT/shared (`100.64.0.0/10`), IPv6 site-local, and non-resolving hosts
are rejected.

Tunables and recommended optionals (timestamps, rate limits, upload caps,
SSO handoff timings, asset-proxy caps, refresh-token lifetime, metrics
token) are documented in `.env.example`.

## OAuth Setup

Configure the Canva OAuth provider to use:

- Authorisation endpoint: `<broker-base-url>/oauth/authorise`
- Token endpoint: `<broker-base-url>/oauth/token`
- Revocation endpoint: `<broker-base-url>/oauth/revoke`
- Userinfo endpoint: `<broker-base-url>/oauth/userinfo`

The OAuth popup is intentionally outside the Canva iframe. Users supply
their ResourceSpace base URL (the address they normally use). When SSO is
off they also supply a username and password.

The broker accepts any public HTTPS ResourceSpace URL. If
`RESOURCE_SPACE_ALLOWED_HOSTS` is set, unknown hosts that match neither that
suffix list nor an exact `RESOURCE_SPACE_TENANTS_JSON` record are rejected.
It then authenticates against that exact ResourceSpace instance and returns
an authorisation code to Canva.

In live mode, tenant resolution also refuses any tenant URL that resolves to
a private, loopback, link-local, reserved, multicast, CGNAT/shared
(`100.64.0.0/10`), IPv6 site-local, or otherwise non-globally-routable
address, and fails closed on hosts that do not resolve at all (SSRF
protection). This check applies to every tenant the broker will call,
including exact registry records and dynamically entered URLs, so a
mis-set or tampered configuration cannot turn the broker into an
internal request sink.

Every outbound fetch to a tenant (the login POST, the signed session-key
validation and API calls), the signed-asset proxy, AND the Canva export
download (per redirect hop) is DNS-pinned: the host is resolved and validated
once, and the connection is made to that exact validated IP (the original host
is kept for the TLS SNI/certificate check and the `Host` header). This closes
the DNS-rebinding window where a host could answer with a public address during
validation and an internal address at connect time. All validated addresses are
tried in turn, IPv4 first, so a host that resolves to IPv6 first still connects
where outbound IPv6 is unavailable (Railway disables it by default). The host is
canonicalised with UTS46 IDNA (via `httpx.URL.raw_host`) before it is validated
and resolved, so the address that is checked is exactly the one httpx connects
to (the stdlib IDNA-2003 codec is not used: it maps e.g. `faß.de` to the
different domain `fass.de`). Allowlist patterns (tenant, asset and export) and
the configured-tenant identity match are canonicalised the same way, preserving
a leading dot, so a Unicode host matches a Unicode pattern and a configured
tenant is found regardless of whether the request or the record uses the Unicode
or punycode form. An invalid DNS label (e.g. a label over 63 bytes) is a
controlled rejection, not a 500. These clients set `trust_env=False`: an
environment `HTTPS_PROXY` would CONNECT-tunnel past the pin and verify TLS
against the pinned IP, so it is disabled. On the async asset-proxy path the
blocking DNS lookup runs off the event loop, and the validated addresses race to
a response header under a single hard connect deadline (staggered,
Happy-Eyeballs style); only the winning connection's body is then streamed
(outside that deadline, with its own read timeout), so a black-holed address
neither blocks the worker, delays fallback, nor buffers multiple bodies.

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
    "clientId": "partner-client",
    "integration": "partner-integration",
    "redirectUriAllowlist": ["https://partner.example/callback"]
  }
]
```

## ResourceSpace Hosted-Login (SSO)

When enabled, the sign-in page collects only the ResourceSpace URL. **Sign
in** hands the browser off to the tenant's own login page, so the tenant's
SAML, MFA, native password, or an existing browser session completes
sign-in. Username and password are not collected in the Canva popup. Off
by default. The popup change is UI-only: `POST /oauth/authorise` still
accepts `auth_method=password` when the flag is on, for tests and rollback.

- `RESOURCE_SPACE_SSO_ENABLED=false` (default): the sign-in page shows the
  password form and `POST /oauth/sso/callback` returns `404`. Set to
  `true` to show the hosted-login **Sign in** page (ResourceSpace URL only)
  and enable the callback.
- `POST /oauth/authorise` accepts an `auth_method` form field: `password`
  (default, still honoured when SSO is on) or `sso`.
- On `auth_method=sso`, the broker redirects to
  `<tenant-base-url>/pages/user/user_api_session.php?system=<RESOURCE_SPACE_SSO_SYSTEM_KEY>&state=<handoff-state>`.
  `RESOURCE_SPACE_SSO_SYSTEM_KEY` (default `canva`) must match the
  ResourceSpace destination registered for this integration.
- The `state` in that URL is a single-use handoff state the broker
  generates itself; it is never Canva's own `state` value. Canva's `state`
  is stored server-side against the handoff and returned unchanged once the
  handoff completes, so it cannot be used as the callback secret.
- `RESOURCE_SPACE_SSO_PENDING_TTL_SECONDS` (default `600`) controls how long
  that handoff state stays valid, long enough for SAML/MFA at the tenant.
- `RESOURCE_SPACE_SSO_REPLAY_RETENTION_SECONDS` (default `600`) controls how
  long a used or expired handoff state is retained as a tombstone after
  expiry, so `POST /oauth/sso/callback` can tell a replay or an expiry apart
  from an unknown/forged state in its logs.
- ResourceSpace calls `POST /oauth/sso/callback` **server-side**, posting
  `state`, `sessionkey`, `username`, `email` and `fullname`. It treats only HTTP
  200 as success, reads the JSON body, and (with Dan's SSO redirect patch
  applied) responds to the browser with **HTTP 303** to the validated
  `redirectUrl`. The broker callback itself always returns JSON, not a 3xx:
  - success: `200` with `{"message": ..., "redirectUrl": ...}`, where
    `redirectUrl` is the Canva `redirect_uri` plus a fresh authorisation `code`
    and Canva's original `state` (correct casing preserved).
  - failure: a non-200 status with `{"message": ..., "reason": ...}`, where
    `reason` is a machine-readable class (`sso_state_invalid`,
    `sso_state_expired`, `sso_state_replay`, `sso_handoff_failed`,
    `resourcespace_token_validation_failed`). ResourceSpace shows `message`
    and the HTTP code; `reason` is for our logs and support.
- The broker validates the returned session key with a signed
  `get_resource_types` call (no parameters; returns a JSON array of configured
  resource types) before minting any token. Validity is defined strictly as
  "the response decodes to a JSON list". ResourceSpace can signal failure with
  an HTTP 200 and a falsy body as often as with 401/403, so anything that is
  not a list is a failed validation and mints no token.
- A callback with no `username` fails before any upstream call; the broker
  never invents a username to complete the flow. The callback username is sent
  to ResourceSpace with **exact casing** for signing; the broker's internal
  user id lowercases the username for `sub` — confirm with the tenant that RS
  cannot hold distinct accounts whose names differ only by case.
- **ResourceSpace dependency:** Dan's SSO redirect patch (303 to `redirectUrl`
  after a successful callback) must be present on the tenant. Re-verify after
  every ResourceSpace upgrade before leaving `RESOURCE_SPACE_SSO_ENABLED=true`.
- **Enable SSO only after live browser UAT:** confirm the OAuth popup follows
  ResourceSpace's 303, lands on the Canva redirect URI with unchanged `state`,
  exchanges the code, and creates a working session (the consent form uses
  `CentralSpacePost`; the test must prove the PHP `Location` navigates the popup).
- Structured log events, all free of secrets, session material, and direct PII
  (passwords, email addresses, session keys) and keyed by a `correlationId`:
  `oauth_sso_initiated`, `oauth_sso_callback_received`,
  `oauth_sso_state_invalid`,
  `oauth_sso_state_expired`, `oauth_sso_state_replay`,
  `oauth_sso_handoff_failed`, `oauth_sso_token_validation_succeeded`,
  `oauth_sso_token_validation_failed`, `oauth_sso_callback_completed`,
  `store_decrypt_failed`, `store_prune_failed`. Initiation and callback events
  also log `transportPeerHash`, `resolvedClientHostHash`, `clientIpHeaderPresent`,
  and `clientIpHeaderTrusted` (keyed HMAC pseudonyms — not raw IPs). Set
  `CLIENT_IP_LOG_DIAGNOSTICS=true` with `APP_ENV=staging` or `uat` to also log raw
  `transportPeer` while tuning `TRUSTED_PROXY_HOSTS`; startup rejects this flag
  in every other environment.
- **Enablement prerequisite:** before setting `RESOURCE_SPACE_SSO_ENABLED=true`
  on Railway (or any reverse-proxy deployment), verify from two distinct
  end-user networks that `resolvedClientHostHash` differs between
  `oauth_sso_initiated` events and `clientIpHeaderTrusted` is `true`. Callback
  logs share the ResourceSpace server identity (server-side); verify trust
  and source stability there, not per-user variation. If every initiation
  collapses to the same hash, extend `TRUSTED_PROXY_HOSTS` with the observed
  transport peer before treating SSO per-source quotas as effective (see
  [Deployment runbook](./DEPLOYMENT-RUNBOOK.md)).

Identity field mapping (ResourceSpace callback into the bridge session):

- `username`: used verbatim (original case) to sign ResourceSpace API calls,
  and lower-cased only to derive the internal `user.id`
  (`<tenant-id>:<username>`). This matches the existing password flow, so
  `/api/session`, `/oauth/userinfo` and revoke-by-user keep working unchanged.
- `fullname` / `email`: present on the ResourceSpace callback POST but **not
  trusted**. Only `username` and `sessionkey` are validated upstream; display
  name is taken from the validated session (fixture user record or username in
  live mode). Email is omitted from userinfo until a trusted upstream source
  exists.
- The confirmed callback carries no ResourceSpace user id, so `user.id` is
  derived as above. Only `username` and a valid `sessionkey` are required.

Token retention and cleanup:

- Access tokens `TOKEN_TTL_SECONDS` (default 900s); authorisation codes
  `AUTH_CODE_TTL_SECONDS` (default 300s, single-use); refresh tokens
  `REFRESH_TOKEN_TTL_SECONDS` (default 2592000s / 30 days, now configurable, a
  shorter value is recommended for UAT); pending SSO state
  `RESOURCE_SPACE_SSO_PENDING_TTL_SECONDS` (600s) plus a
  `RESOURCE_SPACE_SSO_REPLAY_RETENTION_SECONDS` (600s) tombstone.
- Expiry is lazy on store transactions: expired records are pruned inside the
  next read/write, and pending SSO states are pruned on their `purgeAt` so
  replay and expiry stay distinguishable until then.
- A background prune task runs every `STORE_PRUNE_INTERVAL_SECONDS` (default
  3600; set `0` to disable) to remove expired records from dormant brokers
  without waiting for the next OAuth transaction.

CSRF / cross-site handling:

- The callback is an unauthenticated backchannel POST from ResourceSpace, so no
  broker cookie can bind it. The controls are Canva's own `state` (validated by
  Canva) plus the broker's single-use handoff `state`, which is bound to the
  originating client, redirect URI and Canva state; the minted `code` is
  PKCE-bound, so it is unusable without the verifier held by the Canva client.

Known items for a future production rollout, not action items for the
current UAT-grade deployment:

- The JSON store (`STORAGE_PATH`) holds OAuth tokens and pending SSO handoff
  state in cleartext, but sensitive session fields (`upstream.sessionKey`,
  `user.email`) are Fernet-encrypted when `STORAGE_ENCRYPTION_KEY` is set
  (required outside development/test). Cleartext records from before
  encryption was enabled continue to work: decrypt passes through unprefixed
  values and records self-heal as tokens rotate. Key rotation requires a new
  key plus deleting the store (users re-authenticate); `MultiFernet` zero-downtime
  rotation is a future option. Residual risk: the encryption key and store file
  live on the same host, so a full host compromise exposes both.
- The rate limiter is in-memory per process and is not shared across
  replicas; `railway.toml` pins `numReplicas = 1` for this reason, which
  needs to remain the case until a shared store backs the limiter.

For the tenant-side SAML/Entra configuration this handoff depends on (the
ResourceSpace SimpleSAML plugin wiring and the Microsoft Entra Enterprise
Application).

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
- The broker's own `oauth_authorize_completed` log event records the tenant
  host only, never the username or the full tenant URL.

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

Keep tenant URL SSRF guards, OAuth bearer-token checks, ResourceSpace permission
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
- Constant-time signature comparison (`hmac.compare_digest`) on both the GET
  and POST paths, so a timing side-channel cannot be used to guess a valid
  signature

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

## Asset Proxy Hardening

The signed preview/download endpoints (`GET /public/assets/:grantId`,
`GET /signed/assets/:grantId`) proxy bytes from the ResourceSpace tenant on
a verified grant. Before connecting, the broker enforces:

- `https://` only
- A present hostname
- Optional exact-match host allowlist via `RESOURCE_SPACE_ASSET_ALLOWED_HOSTS`
  (empty means any public host)
- Refusal of any URL whose host resolves to a private, loopback,
  link-local, reserved, or multicast IP
- Redirects are not followed, so a redirect cannot pivot the fetch to an
  unvalidated host
- Streamed download with a `RESOURCE_SPACE_ASSET_PROXY_MAX_BYTES` cap
  (default 50 MiB); the fetch aborts without returning partial content if
  the cap is exceeded
- `Content-Disposition` filenames are sanitised: control characters are
  stripped, and an RFC 5987 `filename*` is emitted alongside an ASCII-only
  fallback, so a hostile filename cannot inject response headers

## Storage Hardening

The JSON store (`STORAGE_PATH`) holds OAuth access/refresh tokens and
pending SSO handoff state in cleartext, but sensitive session fields
(`upstream.sessionKey`, `user.email`) are Fernet-encrypted when
`STORAGE_ENCRYPTION_KEY` is set (required outside `development`/`test`).
Outside `development`/`test`, a failed `chmod` on the store file (for
example an unwritable mount) is a fatal startup error rather than a silent
warning, because it could otherwise leave token records world-readable. In
`development`/`test` a failed chmod is tolerated so local work stays
frictionless.

Key rotation: generate a new Fernet key, delete the store file, restart the
broker, and have users re-authenticate. Cleartext records from before
encryption was enabled continue to work until they expire; prefixed values
self-heal as tokens rotate.

## Failure Modes

- `INVALID_TENANT_URL`: malformed tenant URL entered in the OAuth popup
- `FORBIDDEN`: tenant URL resolved to a private or non-public address, or
  could not be resolved at all (a mistyped custom domain included). The
  sign-in page shows the specific reason.
- `UNKNOWN_TENANT`: tenant URL was rejected by an optional
  `RESOURCE_SPACE_ALLOWED_HOSTS` suffix list (or, in fixture mode, is not a
  seeded demo tenant)
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
- Leave `RESOURCE_SPACE_ALLOWED_HOSTS` empty so custom domains and
  self-hosted instances work. Set it only to lock the broker to known
  hostname suffixes.
- Leave `RESOURCE_SPACE_TENANTS_JSON=[]` unless an instance needs an
  override such as an explicit `apiUrl`
- Set `CANVA_CLIENT_SECRET`, `OAUTH_CLIENT_ID`,
  `OAUTH_REDIRECT_URI_ALLOWLIST`, `CORS_ORIGIN`
- Leave `OAUTH_CLIENTS_JSON` unset unless the broker is intentionally serving
  additional integrations; if set, verify each client's redirect allowlist is
  client-specific
- Leave `RESOURCE_SPACE_SSO_ENABLED=false` until live browser SSO UAT passes
  (303 redirect, unchanged `state`, working session) and Dan's ResourceSpace SSO
  redirect patch is confirmed on the tenant (re-check after RS upgrades); see
  the deployment runbook
- If enabling SSO, confirm distinct `resolvedClientHostHash` values in
  `oauth_sso_initiated` from two end-user networks and stable callback source
  identity in `oauth_sso_callback_received` (see Deployment runbook) and review
  the `oauth_sso_*` log events for the validation run for unexpected
  `oauth_sso_state_*` failures
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
