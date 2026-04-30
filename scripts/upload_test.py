"""End-to-end upload + preview probe against a ResourceSpace tenant.

Runs the full upload pipeline in one shot so you can see what works and
what doesn't:

  1. login
  2. create_resource
  3. upload_multipart (tries multipart field names "file" then "userfile")
  4. get_resource_data       — inspect file_extension, etc.
  5. get_resource_path       — verify file bytes in filestore
  6. create_previews         — try several extension/thumbonly variants
  7. upload_multipart previewonly=1 — generate a JPEG thumbnail with
     Pillow and submit it as a custom preview (skipped if Pillow is not
     installed)

Stops step 3 at the first upload variant that stores the file; runs
every create_previews variant even if one succeeds, so you can see which
shapes the tenant accepts.

Usage:
    python scripts/upload_test.py \
        --base-url https://your-rs.example.com \
        --username USER \
        --password PASS \
        --image /path/to/image.png
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
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


def show(label: str, response: httpx.Response) -> None:
    print(f"--- {label} ---")
    print(f"HTTP {response.status_code}")
    body = response.text
    if len(body) > 1200:
        body = body[:1200] + "…"
    print(f"Body: {body}")
    print()


def parse_body(response: httpx.Response):
    try:
        return response.json()
    except ValueError:
        return response.text.strip()


def call_get(api_url: str, username: str, label: str, session_key: str, params: dict) -> httpx.Response:
    url = sign(api_url, username, session_key, params)
    print(f"GET {url}")
    with httpx.Client(timeout=60.0) as client:
        r = client.get(url)
    show(label, r)
    return r


def call_upload(
    api_url: str,
    username: str,
    label: str,
    session_key: str,
    params: dict,
    field: str,
    filename: str,
    file_bytes: bytes,
    content_type: str,
) -> httpx.Response:
    url = sign(api_url, username, session_key, params)
    print(f"POST {url}  [multipart field='{field}']")
    with httpx.Client(timeout=120.0) as client:
        r = client.post(url, files={field: (filename, file_bytes, content_type)})
    show(label, r)
    return r


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--base-url", required=True, help="ResourceSpace base URL, e.g. https://rs.example.com")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--image", required=True, type=Path, help="Path to a PNG/JPEG file to upload")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    api_url = f"{base_url}/api/"
    image_path: Path = args.image

    if not image_path.exists():
        print(f"File not found: {image_path}")
        return 1

    file_bytes = image_path.read_bytes()
    print(f"Will upload {len(file_bytes):,} bytes from {image_path.name}\n")

    # 1. LOGIN
    print("=== 1. LOGIN ===")
    login_url = f"{api_url}?{urlencode({'function': 'login', 'username': args.username, 'password': args.password})}"
    print(f"GET {login_url}")
    with httpx.Client(timeout=60.0) as client:
        r = client.get(login_url)
    show("login", r)
    session_key = parse_body(r)
    if not isinstance(session_key, str) or not session_key or session_key == "false":
        print(">>> login failed")
        return 1
    print(f"session_key = {session_key}\n")

    # 2. CREATE_RESOURCE
    print("=== 2. CREATE_RESOURCE ===")
    r = call_get(
        api_url,
        args.username,
        "create_resource",
        session_key,
        {"function": "create_resource", "resource_type": 1, "archive": 0},
    )
    ref_value = parse_body(r)
    if not str(ref_value).strip().lstrip("-").isdigit():
        print(f">>> create_resource failed: {ref_value!r}")
        return 1
    ref = str(ref_value).strip()
    print(f"Created resource ref = {ref}\n")

    # 3. UPLOAD_MULTIPART (try both field names)
    print("=== 3. UPLOAD_MULTIPART ===")
    upload_params = {
        "function": "upload_multipart",
        "ref": ref,
        "no_exif": 0,
        "revert": 0,
    }
    for label, field in [("file", "file"), ("userfile", "userfile")]:
        r = call_upload(
            api_url,
            args.username,
            f"upload_multipart field={label}",
            session_key,
            upload_params,
            field,
            image_path.name,
            file_bytes,
            "image/png",
        )
        body = parse_body(r)
        # HTTP 400 with {error:true} = file stored, preview step failed.
        # HTTP 200 with numeric/1/true = full success.
        # Otherwise = bad call, try next variant.
        if r.status_code == 200 or (
            r.status_code >= 400 and isinstance(body, dict) and body.get("error") is True
        ):
            print(f">>> file bytes stored via field='{field}'\n")
            break
    else:
        print(">>> no upload variant accepted; cannot continue")
        return 1

    # 4. GET_RESOURCE_DATA
    print("=== 4. GET_RESOURCE_DATA ===")
    call_get(
        api_url,
        args.username,
        "get_resource_data",
        session_key,
        {"function": "get_resource_data", "resource": ref},
    )

    # 5. GET_RESOURCE_PATH (verify file bytes in filestore)
    print("=== 5. GET_RESOURCE_PATH ===")
    for ext in ["png", "jpg"]:
        call_get(
            api_url,
            args.username,
            f"get_resource_path ({ext})",
            session_key,
            {
                "function": "get_resource_path",
                "ref": ref,
                "extension": ext,
                "page": 1,
                "watermarked": 0,
            },
        )

    # 6. CREATE_PREVIEWS (try variants)
    print("=== 6. CREATE_PREVIEWS ===")
    variants = [
        ("create_previews (png)", {"function": "create_previews", "ref": ref, "extension": "png"}),
        ("create_previews (jpg)", {"function": "create_previews", "ref": ref, "extension": "jpg"}),
        ("create_previews (no extension)", {"function": "create_previews", "ref": ref}),
        (
            "create_previews (thumbonly, png)",
            {"function": "create_previews", "ref": ref, "thumbonly": 1, "extension": "png"},
        ),
    ]
    for label, params in variants:
        call_get(api_url, args.username, label, session_key, params)

    # 7. UPLOAD A CUSTOM PREVIEW via upload_multipart previewonly=1
    print("=== 7. UPLOAD CUSTOM PREVIEW (previewonly=1) ===")
    try:
        from io import BytesIO
        from PIL import Image  # type: ignore[import-not-found]

        im = Image.open(BytesIO(file_bytes))
        im = im.convert("RGB")
        im.thumbnail((1000, 1000))
        buf = BytesIO()
        im.save(buf, format="JPEG", quality=85)
        preview_bytes = buf.getvalue()
        print(f"Generated {len(preview_bytes):,} bytes of JPEG preview")

        call_upload(
            api_url,
            args.username,
            "upload_multipart previewonly=1",
            session_key,
            {
                "function": "upload_multipart",
                "ref": ref,
                "no_exif": 1,
                "revert": 0,
                "previewonly": 1,
            },
            "file",
            "preview.jpg",
            preview_bytes,
            "image/jpeg",
        )

        # Re-fetch state to see if has_image flipped
        call_get(
            api_url,
            args.username,
            "get_resource_data (after preview upload)",
            session_key,
            {"function": "get_resource_data", "resource": ref},
        )
    except ImportError:
        print("Pillow not installed in venv; skipping. Run: .venv/bin/pip install Pillow")

    print(f"Done. View resource: {base_url}/pages/view.php?ref={ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
