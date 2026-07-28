"""Hermes Vault v2.2 — encrypted backend for executor plugins.

Only a non-sensitive health check is registered as an LLM-visible tool.
Secret writes, key rotation and capability handling are local/internal APIs.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

VERSION = "2.2.0"


def _core():
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))).expanduser()
    lib = (home / "lib").resolve()
    if str(lib) not in sys.path:
        sys.path.insert(0, str(lib))
    from hermes_core_loader import load_secret_core
    core = load_secret_core(("VaultStore", "require_version"))
    core.require_version((2, 2, 0))
    return core.VaultStore


def vault_health() -> dict:
    raw = _core()().health()
    return {
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
