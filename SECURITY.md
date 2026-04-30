# Security Policy

`resourcespace-platform` is the tenant-aware OAuth and content broker for
the ResourceSpace Canva DAM integration. It handles tenant credentials,
OAuth tokens, and proxied access to ResourceSpace instances, so we take
security reports seriously and aim to respond quickly.

This policy applies to the code in this repository. Maintainer of record:
SpotDev Services Ltd.

## Reporting a vulnerability

Please report suspected security issues privately. Do **not** open a public
GitHub issue, discussion, or pull request that describes a vulnerability
before it is fixed.

- **Primary channel:** email `support@spotdev.co.uk` with a subject line
  beginning `[security]`.

To help us reproduce and assess the issue quickly, please include:

- A proof-of-concept (minimal reproduction steps, request/response pairs,
  or a short script) that demonstrates the impact.
- The affected version and, if possible, the specific commit SHA or
  deployed environment you tested against.
- Your preferred disclosure timeline, including any conference or
  publication deadlines you are working to.
- Whether you would like to be credited, and if so, the name or handle to
  use.

If you need to send sensitive material and would prefer encrypted
transport, say so in your initial email and we will agree a mechanism
before you send details.

## Response SLA

We measure the targets below in UK business days (Monday to Friday,
excluding UK public holidays).

- **Acknowledgement:** within **2 business days** of receipt. The
  acknowledgement confirms we have the report and names a triage owner.
- **Triage and severity assessment:** within **5 business days** of
  acknowledgement. At this point we will share our initial severity
  rating, reproduction status, and a provisional remediation plan.
- **Fix timeline:** agreed in partnership with Montala Limited on a
  case-by-case basis, weighted by CVSS v3.1 severity, exploitability in
  the wild, and the affected release lines. We will share the agreed
  target with the reporter in writing.

## Supported versions

`resourcespace-platform` is pre-1.0 and under active development. We only
backport security fixes to the latest tagged release line and `main`.

| Version  | Supported           |
| -------- | ------------------- |
| `0.1.x`  | Yes                 |
| `main`   | Yes (tracking HEAD) |
| `< 0.1.x`| No                  |

Once we cut a 1.0 release, this table and the support window will be
revised.

## Scope

The following components of this repository are in-scope for security
reports:

- The broker's HTTP API surface, including authentication, authorisation,
  rate limiting, and input validation on all public and internal
  endpoints.
- OAuth flows handled by the broker, including state and PKCE handling,
  redirect URI validation, and token exchange with Canva and
  ResourceSpace.
- The fixture and live ResourceSpace adapters, including request signing,
  error handling, and any code paths that relay customer content.
- Tenant isolation boundaries: anything that could allow one tenant to
  read, write, or infer the existence of another tenant's configuration,
  tokens, or content.
- Token and secret handling: storage, logging, redaction, rotation, and
  transport of OAuth tokens, API keys, and tenant credentials.

## Out of scope

The issues below are not in-scope for this repository. We will still read
reports in these areas, but we will typically redirect you rather than
treat them as vulnerabilities in `resourcespace-platform`:

- **ResourceSpace core.** ResourceSpace is maintained upstream by Montala
  Limited at montala.com. Please report ResourceSpace vulnerabilities to
  Montala directly; we are happy to help coordinate where a report also
  affects the broker.
- **The Canva platform itself.** Issues in Canva's apps, SDKs, or
  infrastructure should be reported through Canva's own security
  disclosure process.
- **Third-party dependencies.** Please report vulnerabilities in upstream
  libraries to those projects first. We will assess the impact on the
  broker and patch or pin as appropriate once an upstream fix or
  workaround is available.
- **Denial-of-service issues on dev or fixture deployments.** Fixture,
  demo, and development environments are not sized for production load
  and are expected to be brittle under stress. DoS reports against
  production tenants remain in-scope.
- **Self-XSS** and other issues that require a user to paste attacker
  code into their own browser console or otherwise attack themselves.

Reports about missing "best-practice" HTTP headers, TLS configuration on
third-party CDNs, or automated scanner output without a demonstrated
impact will usually be closed as informational.

## Coordinated disclosure

We follow a coordinated disclosure model.

- The default embargo is **90 days from the date we triage the report**,
  or until a patched release is generally available, whichever comes
  sooner.
- We are happy to negotiate a shorter or longer embargo where the
  reporter has a reasonable need (for example, an imminent talk or an
  upstream fix that requires more time).
- Once a fix is released, we will publish a brief advisory in the
  repository release notes describing the issue, affected versions, and
  mitigation. Reporters will be credited by name or handle in those
  release notes if they wish; we will not name reporters who prefer to
  remain anonymous.

If a vulnerability is being actively exploited in the wild, we reserve
the right to ship a fix and publish an advisory ahead of the agreed
embargo. We will tell the reporter before we do so whenever possible.

## Safe harbour

We welcome good-faith security research against your own test deployments
of the broker and any environments we explicitly nominate in a report
thread.

While acting in good faith under this policy, you may:

- Probe, fuzz, and exercise the broker's APIs and OAuth flows against
  test deployments.
- Hold testing accounts, create scratch tenants, and generate synthetic
  content needed to demonstrate an issue.

While acting in good faith under this policy, you must:

- Not attempt to access, modify, or exfiltrate real customer data, real
  ResourceSpace instances belonging to anyone other than yourself, or
  production Canva accounts that are not your own.
- Stop testing and contact us immediately at `support@spotdev.co.uk` at
  the first sign of personal data, customer credentials, or other
  non-public information being exposed.
- Avoid techniques that degrade service for other users, including
  volumetric denial-of-service, resource exhaustion against shared
  infrastructure, or social engineering of SpotDev, Montala, or any
  third-party staff.
- Keep details of any vulnerability confidential until the embargo
  agreed under "Coordinated disclosure" expires.

Research conducted in line with this policy will not be pursued as a
violation of our terms of service, and we will make a good-faith effort
to work with you rather than against you. If in doubt about whether a
particular test is in-scope, ask first at `support@spotdev.co.uk` and we
will clarify in writing before you proceed.
