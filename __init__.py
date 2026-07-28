"""
hermes-vault — AEAD Secret Management Plugin for Hermes Agent.
stdlib-only, zero-dependency secret wrapping with ChaCha20Poly1305.
"""

from . import vault
from . import vault_aead

VERSION = "1.0.0"

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
        handler=vault.wrap
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
        handler=vault.unwrap
    )
    ctx.register_tool(
        name="vault_health",
        toolset="vault",
        schema={"type": "object", "properties": {}},
        handler=vault_aead.vault_health
    )