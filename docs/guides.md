# Guides

## Configuration
- **Keys**: Provide `Keys` with a JWKS URL. First load is synchronous; refresh happens automatically based on TTL.
- **ConfigSession.header**: Must contain `alg` and `kid` for JWS/JWE operations.
- **ConfigSession.key**: Private key for signing and JWE decryption. Bytes (PEM) or `Key`.
- **Audience**: If set, `Session.aud` setter will only accept values from the list.
- **TLS for JWKS**: `Keys(..., verify_tls=True)` enables TLS verification for both sync (`requests`) and async (`aiohttp`) fetches.

## Claims lifecycle
- When calling `session.jwt`:
  - `jti` regenerated
  - `sid` generated once if absent
  - `iat`, `nbf`, `exp` set using `expires`
  - `trace` computed from `Trace` and `jti`

## Merge semantics (`session + jwt_str`)
- All decoded claims are copied into the current session.
- Claims listed in `Session.merge_attributes` are merged (default: `("_payloads", "scope")`).
- Dicts are deep-merged; lists are deduplicated (order is not guaranteed).

## JWE usage
- `serialize(payload, header)` uses recipient public key by `kid` from `Keys`.
- `deserialize(token)` requires `ConfigSession.private`.

## Validation options
- `Session.options` always enforces:
  - `version` fixed value
  - `sid` fixed value only when `Session.sid` already exists
  - `trace` validated via `Trace.validate`
  - Optional audience whitelisting when configured

## Operational tips
- Current `Keys` implementation:
  - First JWKS load is synchronous via `requests.get(self.url)` without an explicit timeout
  - Background refresh uses `aiohttp.ClientSession().get(self.url, ssl=...)` where `ssl` is controlled by `verify_tls`
- Practical recommendations (adapt to your environment):
  - Add explicit timeouts and retries by wrapping or subclassing `Keys`
  - Keep TLS verification enabled (`verify_tls=True`) for trusted HTTPS sources; disable only in tests

## Security best practices
- Rotate keys periodically; prefer short `expires`.
- Restrict audiences; validate tokens with `SessionClaims` where possible.
- Avoid logging sensitive claims or raw tokens.
