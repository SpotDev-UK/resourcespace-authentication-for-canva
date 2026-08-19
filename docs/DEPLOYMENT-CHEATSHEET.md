# Deployment Cheatsheet

A one-page reference for anyone deploying their own broker. Walks through
the values you need to capture from your Canva app, the env vars to set on
your hosting platform, and the post-deploy smoke checks.

For the full deployment narrative (Docker, systemd, container hosts) see
[`README.md`](../README.md#deployment) and the
[Deployment Runbook](./DEPLOYMENT-RUNBOOK.md).

## 1. What you need before you start

- A registered Canva app with the OAuth provider configured to point at
  this broker (you'll fill in the broker URL in step 4).
- A ResourceSpace instance the broker can reach over HTTPS.
- A hosting platform that can run a Python 3.11+ container (Railway, Fly,
  Cloud Run, ECS, Kubernetes, plain Docker, or a VM with systemd).

## 2. Capture the values your broker needs

| Value | Where to get it |
|---|---|
| Canva OAuth client id | Canva Developer Portal → your app → Authentication provider |
| Canva client secret (base64) | Canva Developer Portal → your app → Verification keys |
| Canva app id | Canva Developer Portal → your app → App details |
| Redirect URI(s) Canva will use | Canva Developer Portal → Authentication → "Redirect URIs". Copy the exact strings. |
| ResourceSpace tenant base URL | The URL the customer normally uses, including custom domains and self-hosted instances |
| Broker base URL | Whatever public HTTPS URL your hosting platform exposes for the broker |

## 3. Environment variables

Set these on your hosting platform's secret store. None of them belong in
git. The broker calls a startup validator that refuses to boot in
production if any of the required ones are missing or unsafe.

**Required in production**

| Var | Value |
|---|---|
| `APP_ENV` | `production` (or `staging`). **Defaults to `production` when unset** — the Docker image and systemd unit set this explicitly. Use `development` only on localhost (see `.env.example`). |
| `BASE_URL` | The public HTTPS URL of the broker, e.g. `https://broker.example.com` |
| `OAUTH_ISSUER` | Same as `BASE_URL` unless you have a separate issuer URL |
| `OAUTH_CLIENT_ID` | The primary Canva OAuth client id you captured above (set `OAUTH_ALLOW_DEFAULT_CLIENT_ID=true` if you've kept the `canva-dev-app` placeholder in the Canva Portal) |
| `OAUTH_REDIRECT_URI_ALLOWLIST` | Comma-separated, exact-match list of redirect URIs the primary Canva integration uses |
| `CANVA_CLIENT_SECRET` | The base64 verification secret from the Canva Developer Portal. Verifies signatures on the user-uninstall webhook (Canva → broker, server-to-server). |
| `CANVA_REQUEST_VERIFICATION_MODE` | `required` (gates the user-uninstall webhook; does not apply to `/content/*` since Canva can't sign browser-direct fetches) |
| `ASSET_SIGNING_SECRET` | Long random string. Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `CORS_ORIGIN` | Comma-separated origins Canva uses (typically `https://app-<lowercased-app-id>.canva-apps.com,https://www.canva.com` — the second entry lets the Canva editor fetch image bytes when a user drags an asset onto the canvas) |
| `STORAGE_PATH` | A persistent path that survives restarts, e.g. `/var/lib/resourcespace-platform/platform-store.json` |
| `STORAGE_ENCRYPTION_KEY` | Fernet key for encrypting sensitive store fields at rest. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `RESOURCE_SPACE_MODE` | `live` |
| `CLIENT_IP_HEADER` | Header carrying the original client IP for rate limits and SSO quotas. Defaults to `x-real-ip` outside development/test. Ignored unless the transport peer matches `TRUSTED_PROXY_HOSTS`. |
| `TRUSTED_PROXY_HOSTS` | Comma-separated CIDRs/addresses of reverse proxies that may set `CLIENT_IP_HEADER`. Defaults to RFC1918+loopback+`100.64.0.0/10` outside development/test. Required when `CLIENT_IP_HEADER` is set. Uvicorn `proxy_headers` stays disabled. |

**Recommended (optional)**

| Var | Value |
|---|---|
| `RESOURCE_SPACE_ALLOWED_HOSTS` | Leave empty so any public HTTPS ResourceSpace URL works (custom domains and self-hosted included). Set only to lock the broker to known hostname suffixes. |
| `RESOURCE_SPACE_TENANTS_JSON` | Leave empty unless an instance needs a per-tenant override such as an explicit `apiUrl`. |
| `CANVA_UPLOAD_ALLOWED_HOSTS` | Host allowlist for the `source_url` Canva sends on upload. Capture from logs after the first upload, then tighten. |
| `CANVA_UPLOAD_MAX_BYTES` | Cap on a single upload (default `52428800`, i.e. 50 MiB) |
| `METRICS_TOKEN` | If set, `/metrics` returns the extended posture payload only to bearer-token callers |
| `OAUTH_CLIENTS_JSON` | Optional JSON array for additional OAuth clients, each with `clientId`, optional `integration`, and its own `redirectUriAllowlist`. Leave unset for Canva-only deployments. |
| `OAUTH_REFRESH_GRACE_SECONDS` | Window during which a just-rotated refresh token still works (default `30`) |

If anything is missing, the broker prints a precise startup error naming
each variable.

## 4. Configure the Canva Developer Portal

In the Canva Developer Portal → your app:

| Setting | Value |
|---|---|
| App type | Public app |
| Intent | Design Editor |
| OAuth provider | Custom (the broker) |
| Authorisation endpoint | `<broker-base-url>/oauth/authorise` |
| Token endpoint | `<broker-base-url>/oauth/token` |
| Revocation endpoint | `<broker-base-url>/oauth/revoke` |
| Userinfo endpoint | `<broker-base-url>/oauth/userinfo` |
| Webhook (uninstall) | `<broker-base-url>/webhooks/canva/user-uninstall` |

## 5. Smoke-test the deploy

Run these once after every deploy and after any rollback:

1. `GET /healthz` returns `200 {"ok": true}`.
2. `GET /readyz` returns `200 {"ok": true}`.
3. `GET /metrics` returns aggregate counts (without `METRICS_TOKEN`) or
   the full posture payload (with one).
4. From the Canva app, run one OAuth flow end-to-end. The broker logs
   should show `oauth_authorize_completed`.
5. Run one design upload from Canva. The broker logs should show
   `content_upload_failed` only if the ResourceSpace instance rejected it.

## 6. Discovering allowlist values from the first deploy

Two of the env vars (`OAUTH_REDIRECT_URI_ALLOWLIST` and
`CANVA_UPLOAD_ALLOWED_HOSTS`) depend on values that are specific to your
Canva app and hard to know in advance. The recommended workflow:

1. Run the broker **locally** with default `APP_ENV=development`, or use a
   staging deploy with `APP_ENV=staging` and the full security config.
   Railway refuses `APP_ENV=development` / `test` when `RAILWAY_ENVIRONMENT`
   is set.
2. Complete one OAuth flow and one design export from your real Canva app.
3. Read the broker's structured logs:
   - `oauth_authorize_completed` records the exact `redirect_uri` Canva
     sent.
   - The upload pipeline logs the `source_url` host on each export.
4. Move those values into the env vars above and flip `APP_ENV=production`.

## 7. Where things live

- **Code:** [resourcespace-platform on GitHub](https://github.com/SpotDev-UK/resourcespace-authentication-for-canva).
- **UI repo:** [resourcespace-canva-app on GitHub](https://github.com/SpotDev-UK/resourcespace-canva-app).
- **Secrets:** your hosting platform's secret store. Never in git.
- **State:** the path you set in `STORAGE_PATH`.
- **Licence:** [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
