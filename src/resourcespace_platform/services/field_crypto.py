"""Fernet encryption for sensitive JSON store leaf values."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from cryptography.fernet import Fernet, InvalidToken

ENC_PREFIX = "enc:v1:"


class FieldDecryptError(Exception):
    """Raised when a sealed field cannot be decrypted with the configured key."""


@runtime_checkable
class FieldCipher(Protocol):
    def seal(self, value: str) -> str: ...

    def open(self, value: str) -> str: ...


class NullFieldCipher:
    def seal(self, value: str) -> str:
        return value

    def open(self, value: str) -> str:
        if value.startswith(ENC_PREFIX):
            raise FieldDecryptError(
                "Sealed field cannot be opened without STORAGE_ENCRYPTION_KEY."
            )
        return value


class FernetFieldCipher:
    def __init__(self, key: bytes) -> None:
        self._fernet = Fernet(key)

    def seal(self, value: str) -> str:
        if value.startswith(ENC_PREFIX):
            return value
        token = self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return f"{ENC_PREFIX}{token}"

    def open(self, value: str) -> str:
        if not value.startswith(ENC_PREFIX):
            return value
        ciphertext = value[len(ENC_PREFIX) :]
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise FieldDecryptError("Failed to decrypt sealed field.") from exc


def create_field_cipher(key: str | None) -> FieldCipher:
    if not key:
        return NullFieldCipher()
    try:
        Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise ValueError(
            "STORAGE_ENCRYPTION_KEY must be a url-safe base64-encoded 32-byte Fernet key."
        ) from exc
    return FernetFieldCipher(key.encode("ascii"))
