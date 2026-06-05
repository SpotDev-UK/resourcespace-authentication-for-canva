# UAT Validation Template

A generic checklist for validating an end-to-end deployment of the broker
plus its Canva app against a real ResourceSpace tenant. Copy this file
into your own notes when running UAT and fill in the placeholders. **Do
not commit reviewer credentials, tenant URLs, or any other secret values
back to this repository.**

The scenarios below cover the behaviours every deployment should satisfy
regardless of which ResourceSpace tenant or Canva app is in use.

## Environment

- Broker URL: `<fill-in-broker-base-url>`
- Canva app URL: `<fill-in-app-url>`
- OAuth provider id (in the Canva Developer Portal): `<fill-in-id>`
- ResourceSpace tenant URL: `<fill-in-tenant-url>`
- Reviewer / tester: `<fill-in-name>`
- Validation date: `<fill-in-date>`

## Scenarios

| Scenario | Expected result | Status | Notes |
|---|---|---|---|
| Valid tenant connect | OAuth popup accepts the tenant URL and returns to Canva with a working session | | |
| OAuth client registry isolation | If `OAUTH_CLIENTS_JSON` is configured, each client accepts only its own redirect allowlist and non-Canva clients do not receive `RSCanva` ResourceSpace labelling | | |
| Login request method | ResourceSpace/API gateway logs show the login/session-key exchange as a POST request to the API endpoint | | |
| Login URL credential hygiene | ResourceSpace/API gateway logs for the login attempt do not include `username=` or `password=` in the request URL | | |
| ResourceSpace login user-agent marker | ResourceSpace logs show `RSCanva` in the user-agent for the login/session-key request | | |
| Invalid credentials | Invalid ResourceSpace credentials still fail with the existing invalid-credentials behaviour and no password in logs/errors | | |
| Non-Canva marker exclusion | ResourceSpace-bound test traffic without trusted Canva broker metadata does not receive the `RSCanva` marker | | |
| Invalid host rejection | A tenant URL outside `RESOURCE_SPACE_ALLOWED_HOSTS` is rejected before OAuth completion | | |
| Root browse | Homepage shows the agreed top-level collections/folders and image results | | |
| Browse/search user-agent marker | ResourceSpace logs show `RSCanva` in the user-agent for collection and asset API calls triggered by browsing/searching | | |
| Nested folder browse | Tester can open a child folder/container and continue browsing | | |
| In-folder search | Search inside the current folder returns only in-scope assets for that folder | | |
| Click-to-add | Clicking an image places it into the current Canva design | | |
| Drag-and-drop | Dragging an image into the design succeeds | | |
| Preview/download user-agent marker | ResourceSpace logs show `RSCanva` in the user-agent for preview/download proxy fetches | | |
| Disconnect/reconnect | Tester can disconnect and reconnect without stale-session errors | | |
| Restricted-user filtering | A restricted ResourceSpace user cannot see assets outside their permissions | | |
| Unsupported asset rejection | Unsupported or unavailable assets are rejected by the broker, not added to Canva | | |
| Signed URL expiry | Preview/download grants expire and stale links return `410` or `403` as designed | | |
| Upload from Canva | "Save to ResourceSpace" places the rendered design into the chosen folder with a preview | | |
| Upload user-agent marker | ResourceSpace logs show `RSCanva` in the user-agent for create/upload/preview/link API calls during a Canva save | | |
| Uninstall revocation | The Canva uninstall webhook revokes the local OAuth session for the user/tenant pair | | |

## Sign-off

UAT is complete when every scenario above has passed against your real
ResourceSpace tenant and the broker's structured logs show no unexpected
warnings or errors during the run.

- Tested by: `<fill-in-name>`
- Sign-off date: `<fill-in-date>`
