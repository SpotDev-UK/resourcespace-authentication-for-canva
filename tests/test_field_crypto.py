"""Tests for Fernet field encryption helpers."""
from __future__ import annotations

import json

import pytest
from cryptography.fernet import Fernet

from resourcespace_platform.config import ConfigValidationError, create_config, validate_config_for_environment
from resourcespace_platform.services.field_crypto import (
    ENC_PREFIX,
    FieldDecryptError,
    create_field_cipher,
)


def test_fernet_roundtrip() -> None:
    key = Fernet.generate_key().decode()
    cipher = create_field_cipher(key)
    sealed = cipher.seal("secret-session-key")
    assert sealed.startswith(ENC_PREFIX)
    assert cipher.open(sealed) == "secret-session-key"


def test_seal_is_idempotent() -> None:
    key = Fernet.generate_key().decode()
    cipher = create_field_cipher(key)
    once = cipher.seal("value")
    twice = cipher.seal(once)
    assert once == twice


def test_open_passes_through_cleartext() -> None:
    key = Fernet.generate_key().decode()
    cipher = create_field_cipher(key)
    assert cipher.open("legacy-cleartext") == "legacy-cleartext"


def test_wrong_key_raises_field_decrypt_error() -> None:
    key_a = Fernet.generate_key().decode()
    key_b = Fernet.generate_key().decode()
    sealed = create_field_cipher(key_a).seal("secret")
    with pytest.raises(FieldDecryptError):
        create_field_cipher(key_b).open(sealed)


def test_malformed_key_rejected() -> None:
    with pytest.raises(ValueError, match="STORAGE_ENCRYPTION_KEY"):
        create_field_cipher("not-a-fernet-key")


def test_null_cipher_when_key_empty() -> None:
    cipher = create_field_cipher(None)
    assert cipher.seal("plain") == "plain"
    assert cipher.open("plain") == "plain"
    with pytest.raises(FieldDecryptError):
        cipher.open(f"{ENC_PREFIX}sealed-value")


def test_validator_rejects_production_without_storage_encryption_key() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": "c2VjcmV0",
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "real-canva-client",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
            "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [{"id": "acme", "baseUrl": "https://acme.example.com"}]
            ),
        }
    )
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "STORAGE_ENCRYPTION_KEY" in str(info.value)


def test_validator_rejects_malformed_storage_encryption_key() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": "c2VjcmV0",
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "real-canva-client",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
            "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com",
            "STORAGE_ENCRYPTION_KEY": "not-a-fernet-key",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [{"id": "acme", "baseUrl": "https://acme.example.com"}]
            ),
        }
    )
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "STORAGE_ENCRYPTION_KEY" in str(info.value)


def test_validator_rejects_production_without_tenant_trust_configuration() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": "c2VjcmV0",
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "real-canva-client",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
            "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com",
            "STORAGE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        }
    )
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    message = str(info.value)
    assert "RESOURCE_SPACE_TENANTS_JSON" in message
    assert "RESOURCE_SPACE_ALLOWED_HOSTS" in message
