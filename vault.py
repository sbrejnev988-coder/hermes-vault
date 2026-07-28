"""Strict compatibility wrapper for the shared Hermes secret core.

No XOR fallback and no permissive passthrough on decryption failures.
"""
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


def wrap(secret: str, key_id: str | None = None) -> str:
    return _crypto().vault_wrap_v3(secret, key_id=key_id)


def unwrap(wrapped: str) -> str:
    if not str(wrapped or "").startswith("enc:v3:"):
        raise ValueError("legacy_ciphertext_requires_local_admin_migration")
    return _crypto().vault_unwrap_v3(wrapped)


def health() -> dict:
    raw = _crypto().vault_health()
    return {"available": bool(raw.get("available")), "format": "enc:v3"}
