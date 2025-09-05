# API Reference

This document describes the public API of `xshl.session`.

## Modules
- `xshl.session` — session primitives and helpers
- `xshl.session.keys` — JWKS loading and key lookup
- `xshl.session.claims` — custom claims model

## xshl.session

### Constants (actual values)
- `DEFAULT_SESSION_VERSION = 1` — default session version placed into JWT claims
- `DEFAULT_SESSION_EXPIRES = 120` — default token TTL in seconds
- `DEFAULT_UID = "00000000-0000-0000-0000-000000000000"` — zero UUID placeholder
- `DEFAULT_STR = "undef"` — default string placeholder

### class JsonDumps
Purpose: temporary context manager to override `json.dumps` with a custom `default` function.
- Used internally in `Session.jwt` to serialize claim values (e.g., `datetime`, `Target`) because Authlib's `jwt.encode` doesn't expose a way to pass a `default` to JSON dumping.
- Usage pattern (internal):
  - `with JsonDumps(): jwt.encode(...)`

### class Trace(*args)
Purpose: deterministic request trace linked to JWT `jti`.
- `get(value: str) -> str`: Deterministic UUIDv5 derived from `jti` and trace args.
- `validate(claims: JWTClaims, value: str) -> bool`: Validates `trace` claim.
- `__str__() -> str`: Colon-joined trace values.

### class ConfigSession
Purpose: configuration container for `Session` (keys, app, header, TTL, etc.).
Constructor:
```python
ConfigSession(
    keys: Keys,
    app: uuid.UUID | None = None,
    audience: list[str] | None = None,
    header: dict | None = None,
    version: int = DEFAULT_SESSION_VERSION,
    expires: int = DEFAULT_SESSION_EXPIRES,
    key: bytes | Key | None = None,
)
```
- `keys: Keys`: JWKS provider.
- `app: str`: Issuer UUID string (derived from uuid if provided).
- `audience: list[str] | None`: Allowed audiences.
- `header: dict | None`: JWS/JWE header, must contain `kid` if provided.
- `version: int`: Session version.
- `expires: int`: Token TTL seconds.
- `private: Key | None`: Private key for signing/decryption.

### class Session
Purpose: high-level JWT/JWE session with claims management and token issuing.
Constructor:
```python
Session(config: ConfigSession, *trace_args)
```
- `claims_cls`: overrideable claims class, default `SessionClaims`.
- `trace_cls`: overrideable trace class, default `Trace`.

Dunder methods (wrappers over the internal `_claims` mapping):
- `__add__(other: str) -> Session`: Decode and merge selected claims from external JWT.
- `__len__() -> int`: Number of entries in `_claims`.
- `__contains__(key) -> bool`: Membership check against `_claims` keys.
- `__getitem__(key) -> Any`: Access a claim value from `_claims`.
- `__iter__() -> Iterator[tuple[str, Any]]`: Iterate over `_claims` key/value pairs (skips `None`).
- `keys() -> KeysView[str]`: Keys view of `_claims` (useful for `**session`).
- `update(**kwargs)`: Bulk update with dict-merge behavior for dict attributes.

Claims properties:
- `iss: str` (read-only)
- `sub: str`
- `aud: str` (respects `ConfigSession.audience` if set)
- `sid: str` (read-only)
- `scope: list[str]`
- `path: str | None` (aka `location`)
- `response_type: str | None` (aka `type`)
- `request_scope: str` (aka `_scope`)
- `payloads: dict` (aka `_payloads`)

JWT:
- `jwt -> str | None`: Issues a signed JWT. Sets `jti`, `iat`, `nbf`, `exp`, `trace`. Uses `JsonDumps` context internally for JSON serialization.
- `options -> dict`: Validation options. Includes fixed `version`, `trace` validator, `sid`, and optional audience values.
- `name -> str`: Exposes `keys.name`.

JWE:
- `serialize(value: str | int | bytes, header: dict) -> str`: Produces compact JWE using recipient public key by `kid`.
- `deserialize(value: str | None) -> str | None`: Decrypts JWE with private key.

## xshl.session.claims

### class SessionClaims(JWTClaims)
Purpose: JWT claims subclass with required claims and custom validations.
- `REGISTERED_CLAIMS`: default + custom claims.
- `REQUIRED_CLAIMS`: enforced as essential in options.
- `validate(now=None, leeway=0)`: Extends default validation and validates values for custom claims present in options.

## xshl.session.keys

### Constants
- `DEFAULT_KEYS_TTL = 60` — JWKS cache refresh TTL in seconds
- `API_REFERENCE = "/{version}/{source}/{path}{ext}?target={spot}:{entity}@{base}"` — pattern used by `ReferenceKeys` to build paths

### class Keys
Purpose: load and refresh JWKS; provide lookup by `kid`.
Constructor:
```python
Keys(name: str, url: str, ttl: int = DEFAULT_KEYS_TTL, verify_tls: bool = True)
```
- First load is synchronous via `requests`. Background refresh uses `aiohttp`.
- `verify_tls=True` enables TLS verification for both code paths. Set `False` only in trusted test environments.

Methods/properties:
- `load(background: bool = False) -> None`: Force a JWKS refresh.
- `updated -> bool`: Whether a refresh is required.
- `__call__(kid: str | None) -> Key | KeySet | None`: Return all keys, or find by `kid` if provided.

### class ReferenceKeys(Keys)
Purpose: `Keys` bound to an XSHL `Target`, building the JWKS URL from metadata.
Constructor:
```python
ReferenceKeys(target: Target, trust_url: str, ttl: int = DEFAULT_KEYS_TTL, verify_tls: bool = True)
```
- Builds a JWKS URL using `Target` metadata and `API_REFERENCE` template.

Helper:
- `api_path(item: dict) -> str`: Formats reference path.
