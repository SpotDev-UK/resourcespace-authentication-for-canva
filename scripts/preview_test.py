"""Diagnose preview generation on an existing ResourceSpace resource.

Logs in, fetches the resource's stored metadata (so you can see the
recorded file_extension), then calls create_previews several ways to
find the shape the tenant accepts. Prints every response verbatim.

Usage:
    python scripts/preview_test.py \
        --base-url https://your-rs.example.com \
        --username USER \
        --password PASS \
        --resource REF
"""
from __future__ import annotations

import argparse
import hashlib
from urllib.parse import urlencode

import httpx


def sign(api_url: str, username: str, session_key: str, params: dict) -> str:
    pairs = [("user", username), ("function", str(params["function"]))]
    for key, value in params.items():
        if key == "function" or value is None or value == "":
            continue
        pairs.append((key, str(value)))
    query_string = urlencode(pairs, doseq=False)
    signature = hashlib.sha256(f"{session_key}{query_string}".encode()).hexdigest()
    return f"{api_url}?{query_string}&sign={signature}&authmode=sessionkey"


def call(api_url: str, username: str, label: str, session_key: str, params: dict) -> httpx.Response:
    url = sign(api_url, username, session_key, params)
    print(f"--- {label} ---")
    print(f"GET {url}")
    with httpx.Client(timeout=60.0) as client:
        r = client.get(url)
    print(f"HTTP {r.status_code}")
    body = r.text
    if len(body) > 1200:
        body = body[:1200] + "…"
    print(f"Body: {body}")
    print()
    return r


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--base-url", required=True, help="ResourceSpace base URL, e.g. https://rs.example.com")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--resource", required=True, help="ResourceSpace resource ref to inspect")
    args = parser.parse_args()

    api_url = f"{args.base_url.rstrip('/')}/api/"
    ref = args.resource.strip()

    # Login
    login_url = f"{api_url}?{urlencode({'function': 'login', 'username': args.username, 'password': args.password})}"
    with httpx.Client(timeout=60.0) as client:
        r = client.get(login_url)
    try:
        session_key = r.json()
    except ValueError:
        session_key = r.text.strip().strip('"')
    if not isinstance(session_key, str) or not session_key:
        print("login failed")
        print(r.text)
        return 1
    print(f"session_key = {session_key}\n")

    # Inspect the resource's stored metadata (file_extension, etc.)
    call(api_url, args.username, "get_resource_data", session_key, {"function": "get_resource_data", "resource": ref})
    call(api_url, args.username, "get_resource_path (jpg)", session_key, {"function": "get_resource_path", "ref": ref, "extension": "jpg", "page": 1, "watermarked": 0})
    call(api_url, args.username, "get_resource_path (png)", session_key, {"function": "get_resource_path", "ref": ref, "extension": "png", "page": 1, "watermarked": 0})

    # Try create_previews variations
    call(api_url, args.username, "create_previews (png)", session_key, {"function": "create_previews", "ref": ref, "extension": "png"})
    call(api_url, args.username, "create_previews (jpg)", session_key, {"function": "create_previews", "ref": ref, "extension": "jpg"})
    call(api_url, args.username, "create_previews (no extension)", session_key, {"function": "create_previews", "ref": ref})
    call(api_url, args.username, "create_previews (thumbonly)", session_key, {"function": "create_previews", "ref": ref, "thumbonly": 1, "extension": "png"})

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
