# Быстрый старт

Установка:

```bash
pip install xshl-session
```

Создание провайдера ключей и сессии:

```python
from xshl.session.keys import Keys
from xshl.session import Session, ConfigSession
import uuid

keys = Keys(name="session_name", url="https://example.org/jwks.json")
config = ConfigSession(
    keys=keys,
    app=uuid.uuid4(),
    audience=None,
    header={"alg": "RS256", "kid": "<kid>"},
    version=1,
    expires=3600,
    key=b"<private-key-pem>"
)
session = Session(config, "trace-arg-1", "trace-arg-2")
```

Работа с claims и выпуск JWT:

```python
session.sub = "user-123"
session.aud = "service-api"

jwt_token = session.jwt
```

Слияние внешнего JWT:

```python
session + "<external-jwt>"
```

JWE шифрование/дешифрование:

```python
protected = {"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "<kid>"}
serialized = session.serialize(b"payload", protected)
plaintext = session.deserialize(serialized)
```
