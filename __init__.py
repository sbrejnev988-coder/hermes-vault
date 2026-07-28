"""
hermes-vault — AEAD Secret Management Plugin for Hermes Agent.
stdlib-only, zero-dependency secret wrapping with ChaCha20Poly1305.

Exports: wrap, unwrap, vault_wrap_v3, vault_unwrap_v3, vault_health
"""

import os
import sys

# Add parent to sys.path so memory-wiki can import from us
_plugin_dir = os.path.dirname(os.path.abspath(__file__))
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from . import vault
from . import vault_aead

VERSION = "1.0.0"

# Re-export canonical API
wrap = vault.wrap
unwrap = vault.unwrap
vault_wrap_v3 = vault_aead.vault_wrap_v3
vault_unwrap_v3 = vault_aead.vault_unwrap_v3
vault_health = vault_aead.vault_health


def register(ctx):
    """Register vault providers and tools."""
    ctx.register_tool(
        name="vault_wrap",
        toolset="vault",
        schema={
            "type": "object",
            "properties": {
                "secret": {"type": "string", "description": "Secret value to wrap"},
                "key_id": {"type": "string", "description": "Key identifier for rotation"},
            },
            "required": ["secret"]
        },
        handler=lambda secret, key_id="default", **kw: wrap(secret) if key_id == "default" else vault_aead.vault_wrap_v3(secret, key_id)
    )
    ctx.register_tool(
        name="vault_unwrap",
        toolset="vault",
        schema={
            "type": "object",
            "properties": {
                "wrapped": {"type": "string", "description": "Wrapped secret to unwrap"},
            },
            "required": ["wrapped"]
        },
        handler=lambda wrapped, **kw: unwrap(wrapped)
    )
    ctx.register_tool(
        name="vault_health",
        toolset="vault",
        schema={"type": "object", "properties": {}},
        handler=lambda **kw: vault_aead.vault_health()
    )
