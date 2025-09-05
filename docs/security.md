# Security Notes

- Verify TLS when fetching JWKS. Disabling SSL verification in production is unsafe.
- Use timeouts and retries when loading JWKS to avoid startup stalls.
- Keep private keys out of source control. Load via environment or secret manager.
- Rotate signing keys and `kid` values regularly; set conservative `expires`.
- Validate audience and version when consuming JWTs; use `SessionClaims`.
- Do not log raw JWT/JWE tokens or private claim contents.
- When merging external JWT (`session + token`), ensure you trust the source.
