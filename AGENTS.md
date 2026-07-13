# AGENTS.md

## Cursor Cloud specific instructions

This repo is the **ResourceSpace Platform broker** (Python 3.11+ / FastAPI). See
`README.md` for the full API surface, env vars, and deployment. Notes below are
the non-obvious bits for working in the cloud VM.

### Environment
- The cloud update script creates a per-repo virtualenv at `.venv` and runs
  `pip install -e ".[dev]"`. Use it directly (no need to reinstall):
  - `./.venv/bin/python`, `./.venv/bin/pytest`, or `source .venv/bin/activate`.
- Copy `.env.example` to `.env` for local runs. The committed defaults are
  dev-safe: `APP_ENV=development` and `RESOURCE_SPACE_MODE=fixture`, so the
  broker boots with no real ResourceSpace tenant and no secrets. (In non-dev
  `APP_ENV`, `validate_config_for_environment()` refuses to start until every
  production secret is set — see README "Required environment in production".)

### Run / test
- Run: `./.venv/bin/python -m resourcespace_platform.main` — listens on `$PORT`
  (default `3001`). Health: `GET /healthz`, readiness: `GET /readyz`.
- Tests: `./.venv/bin/pytest` (config in `pyproject.toml`; `asyncio_mode=auto`).
- Import sanity (what CI runs): `python -c "from resourcespace_platform.main import create_app; create_app()"`.
- There is **no Python linter/formatter configured**; CI (`.github/workflows/ci.yml`)
  only does the import check + `pytest`.

### Fixture mode (dev hello-world)
- Fixture tenants/users are in `src/resourcespace_platform/data/fixture_data.py`.
  Working login: user `alice` / `alice-password` on tenant
  `https://acme.demo.resourcespace.local`.
- End-to-end flow without the Canva app: PKCE `POST /oauth/authorise` →
  `POST /oauth/token` → `GET /api/session` / `POST /content/resources/find`.
  `tests/test_authorization.py` shows the exact PKCE round-trip.
- Uploads are **live-only**; fixture mode rejects `POST /content/resources/upload`.
