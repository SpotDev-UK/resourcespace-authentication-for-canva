"""Diagnostic: log into ResourceSpace and call create_resource directly.

Usage:
    python scripts/test_create_resource.py \
        --base-url https://your-rs.example.com \
        --username USER \
        --password PASS \
        [--url https://some-image-url.jpg]

If --url is provided, passes it to create_resource (the one-shot upload
path). Otherwise calls create_resource without a url — useful to isolate
whether it's the URL fetch or the resource creation that's rejected.

Prints the raw ResourceSpace response for each step.
"""
from __future__ import annotations

import argparse
import hashlib
from urllib.parse import urlencode

import httpx


def call(api_url: str, username: str, session_key: str, params: dict) -> object:
    pairs = [("user", username), ("function", str(params["function"]))]
    for key, value in params.items():
        if key == "function" or value is None or value == "":
            continue
        pairs.append((key, str(value)))
    query_string = urlencode(pairs, doseq=False)
    signature = hashlib.sha256(f"{session_key}{query_string}".encode()).hexdigest()
    full_url = f"{api_url}?{query_string}&sign={signature}&authmode=sessionkey"
    print(f"\n>>> {params['function']}")
    print(f"    URL: {full_url}")
    response = httpx.get(full_url, timeout=60.0)
    print(f"    HTTP {response.status_code}")
    print(f"    Body: {response.text[:500]}")
    try:
        return response.json()
    except ValueError:
        return response.text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--url", help="Optional image URL for one-shot upload test")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    api_url = f"{base}/api/"

    print(f"Logging into {base} as {args.username}...")
    login_url = f"{api_url}?{urlencode({'function': 'login', 'username': args.username, 'password': args.password})}"
    login_response = httpx.get(login_url, timeout=60.0)
    print(f"    HTTP {login_response.status_code}")
    print(f"    Body: {login_response.text[:500]}")

    try:
        session_key = login_response.json()
    except ValueError:
        session_key = login_response.text.strip().strip('"')

    if not session_key or session_key in ("false", False):
        print("Login failed.")
        return 1

    print(f"session_key = {session_key}")

    # 1. Read-only sanity check
    call(api_url, args.username, session_key, {"function": "get_user_collections"})

    # 2. Write: create_resource
    params: dict = {
        "function": "create_resource",
        "resource_type": -1,
        "archive": 0,
    }
    if args.url:
        params["url"] = args.url
        params["no_exif"] = 0
        params["revert"] = 0
        params["autorotate"] = 0

    result = call(api_url, args.username, session_key, params)
    print(f"\n==> create_resource result: {result!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
