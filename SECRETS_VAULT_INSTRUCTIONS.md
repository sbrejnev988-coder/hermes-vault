# Secrets vault instructions for Hermes Agent

## Where the vault lives
Protected local vault with real secrets:
```
<HERMES_HOME>/vault/secrets_registry.json
```
Directory: `<HERMES_HOME>/vault`

## Security policy
- Store only path to vault, secret IDs, and non-secret access maps in memory-wiki/shared-memory.
- NEVER copy real passwords/tokens/keys to memory-wiki/shared-memory/final answers.
- Mask secrets in final answers.
- secrets_registry.json: chmod 0600
- vault directory: chmod 0700

## Secret record format
```json
{
  "id": "server.example.main",
  "host": "1.2.3.4",
  "login": "user",
  "password": "***",
  "port": 22,
  "type": "ssh_password",
  "owner_or_context": "description"
}
```

## Usage in Hermes
- `secret_context_lookup(id)` — read a secret from vault (reveal=true for full value)
- `vault_wrap(secret)` — wrap with AEAD before storage
- `vault_unwrap(wrapped)` — unwrap AEAD-protected secret