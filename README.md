# Hermes Vault — AEAD Secret Management for Hermes Agent

stdlib-only, zero-dependency secret wrapping with ChaCha20Poly1305 AEAD + XOR fallback.

## Files
- `vault.py` — Secret wrapping/unwrapping (v1 XOR, v2 AEAD)
- `vault_aead.py` — Vault v3 standard AEAD with key rotation and migration
- `vault_secrets.py` — Secret registry (flat JSON, NOT included — use env var or separate secrets file)
- `plugin.yaml` — Plugin manifest
- `README.md` — This file

## Architecture
```
User config (env/MW_VAULT_KEY)
        ↓
   vault.py / vault_aead.py
        ↓
   enc:v3:<key_id>:<nonce>:<ct>
        ↓
   secrets_registry.json (USER-MANAGED, NOT committed)
```

## Security
- All secrets wrapped with AEAD before storage
- MW_VAULT_KEY env var controls encryption mode
- No raw secrets in plugin code, README, or logs
- chmod 0600 for secrets files

## Usage
```python
from vault import wrap, unwrap

wrapped = wrap("my-api-key")
plain   = unwrap(wrapped)
# plain == "my-api-key"
```

## Integration with memory-wiki
memory-wiki stores redacted secret references (`sec_*` IDs).
Vault handles the actual secret values.
memory-wiki NEVER stores raw passwords/tokens.