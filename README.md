# py-xshl-session
Session in JWT 
=======================

[![PyPI version](https://img.shields.io/pypi/v/xshl-session.svg)](https://pypi.org/project/xshl-session/)
[![Python Version](https://img.shields.io/pypi/pyversions/xshl-session.svg)](https://pypi.org/project/xshl-session/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Python library for managing JWT/JWE sessions with key management and XSHL Target integration.

- 🇷🇺 Russian version: see `README_RU.md`
- 📚 Full docs: `docs/index.md` → [Quickstart](docs/quickstart.md), [Guides](docs/guides.md), [API](docs/api.md), [Security](docs/security.md)
- 🌐 Localized docs (RU): `docs/ru/index.md`

## Features

- 🔐 JWT/JWE support for signing and encryption
- 🎯 XSHL integration: Target-aware JWKS loading
- ⚡ Background refresh of JWKS with TTL
- 🛡️ Extended claims validation via custom `SessionClaims`
- 📦 JWE serialization/deserialization helpers
- 🔍 Built-in request tracing

## Constants
- `DEFAULT_SESSION_VERSION = 1`
- `DEFAULT_SESSION_EXPIRES = 120`
- `DEFAULT_UID = "00000000-0000-0000-0000-000000000000"`
- `DEFAULT_STR = "undef"`

## Quickstart

See `docs/quickstart.md` for a complete guide.

```python
from xshl.session.keys import Keys
from xshl.session import Session, ConfigSession
import uuid

keys = Keys(name="session_name", url="https://example.org/jwks.json")
config = ConfigSession(
    keys=keys,
    app=uuid.uuid4(),
    audience=["service-api"],
    header={"alg": "RS256", "kid": "<kid>"},
    version=1,
    expires=3600,
    key=b"<private-key-pem>"
)
session = Session(config, "trace-1", "trace-2")

session.sub = "user-123"
session.aud = "service-api"
session.scope = ["read", "write"]

jwt_token = session.jwt
```

Note: `Session.jwt` uses a `JsonDumps` context internally to serialize claims because Authlib JWT encoding does not expose a `default` hook for JSON; see API docs.

JWE helpers:

```python
protected = {"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "<kid>"}
serialized = session.serialize(b"payload", protected)
plaintext = session.deserialize(serialized)
```

## Documentation

- API details in `docs/api.md`
- Configuration and operational tips in `docs/guides.md`
- Security recommendations in `docs/security.md`

## License

GPL v3 — see [LICENSE](LICENSE) and [COPYRIGHT](COPYRIGHT).

## Contributing

- Issues and feature requests: open on GitHub
- Pull requests welcome. Please ensure:
  1. Tests pass
  2. Lint/style are respected
  3. Tests are added for new functionality
  4. You understand GPL v3 requirements for contributions 
