"""Strict compatibility API backed by ``hermes_secret_core.crypto``."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _crypto():
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))).expanduser()
    lib = Path(os.environ.get("HERMES_SECRET_CORE_PATH", str(home / "lib"))).expanduser()
    if str(lib) not in sys.path:
        sys.path.insert(0, str(lib))
    from hermes_secret_core import crypto, require_version
    require_version((2, 2, 0))
    crypto.vault_init(keyring_path=str(home / "vault" / "keyring.json"))
    return crypto


def vault_init(key_path: str | None = None, keyring_path: str | None = None) -> None:
    _crypto().vault_init(key_path=key_path, keyring_path=keyring_path)


def vault_is_available() -> bool:
    return _crypto().vault_is_available()


def vault_wrap_v3(plaintext: str, key_id: str | None = None) -> str:
    return _crypto().vault_wrap_v3(plaintext, key_id=key_id)


def vault_unwrap_v3(stored: str) -> str:
    return _crypto().vault_unwrap_v3(stored)


def vault_health() -> dict:
    raw = _crypto().vault_health()
    return {"available": bool(raw.get("available")), "format": "enc:v3"}


def secret_fingerprint(value: str, context: str = "") -> str:
    return _crypto().secret_fingerprint(value, context)
