"""Hermes Vault v2.1 — encrypted backend for executor plugins.

Only a non-sensitive health check is registered as an LLM-visible tool.
Secret writes, key rotation and capability handling are local/internal APIs.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

VERSION = "2.1.0"


def _core():
    # HERMES-SECURITY-INTEGRATION-20260728: fixed-path, SHA-256-pinned secret core.
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))).expanduser()
    lib = home / "lib"
    if str(lib) not in sys.path:
        sys.path.insert(0, str(lib))
    from hermes_core_loader import load_secret_core
    return load_secret_core(("VaultStore",)).VaultStore


def vault_health() -> dict:
    raw = _core()().health()
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))).expanduser()
    lib = home / "lib"
    if str(lib) not in sys.path:
        sys.path.insert(0, str(lib))
    from hermes_core_loader import describe_secret_core
    integrity = describe_secret_core()
    return {
        "core_integrity_ok": bool(integrity.get("integrity_ok")),
        "core_sha256": str(integrity.get("sha256") or ""),
        "core_path": str(integrity.get("path") or ""),
        "available": bool(raw.get("available")),
        "backend": "sqlite-aead-v3",
        "entries": int(raw.get("entries", 0)),
        "active_capabilities": int(raw.get("active_capabilities", 0)),
        "keyring_exists": bool(raw.get("keyring_exists")),
        "keyring_mode": str(raw.get("keyring_mode") or ""),
        "fingerprint_key_exists": bool(raw.get("fingerprint_key_exists")),
        "fingerprint_key_mode": str(raw.get("fingerprint_key_mode") or ""),
    }


def register(ctx):
    ctx.register_tool(
        name="vault_health",
        toolset="vault",
        schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=lambda **kw: vault_health(),
    )
