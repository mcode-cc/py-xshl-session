# py-xshl-session
Session in JWT 
=======================

[![PyPI version](https://img.shields.io/pypi/v/xshl-session.svg)](https://pypi.org/project/xshl-session/)
[![Python Version](https://img.shields.io/pypi/pyversions/xshl-session.svg)](https://pypi.org/project/xshl-session/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Библиотека для управления JWT/JWE сессиями с поддержкой криптографических ключей и интеграцией с XSHL Target system.

## Основные возможности

- 🔐 **JWT/JWE поддержка**: Полная поддержка JSON Web Tokens и JSON Web Encryption
- 🎯 **Интеграция с XSHL**: Работа с Target system для загрузки ключей
- ⚡ **Асинхронная загрузка**: Фоновая загрузка и автоматическое обновление ключей
- 🛡️ **Валидация claims**: Расширенная валидация claims с кастомными правилами
- 📦 **Сериализация/Десериализация**: Поддержка сериализации данных через JWE
- 🔍 **Трассировка**: Встроенная система трассировки запросов

## Установка

```bash
pip install xshl-session
```

Или установите из исходников:

```bash
git clone https://github.com/your-username/xshl-session.git
cd xshl-session
pip install -e .
```

## Быстрый старт

### Создание сессии

```python
from xshl.session import Session, ConfigSession, Keys
import uuid

# Настройка ключей
keys = Keys(
    name="my-app-keys",
    url="https://keys.example.com/jwks.json"
)

# Конфигурация сессии
config = ConfigSession(
    keys=keys,
    app=uuid.UUID("your-app-uuid"),
    audience=["api.example.com"],
    header={"alg": "RS256", "kid": "your-key-id"},
    expires=3600  # 1 час
)

# Создание сессии
session = Session(config, "user123", "device456")

# Установка claims
session.sub = "user-uuid"
session.aud = "api.example.com"
session.scope = ["read", "write"]

# Генерация JWT токена
token = session.jwt
print(f"JWT Token: {token}")
```

### Валидация и декодирование токена

```python
from xshl.session import Session, ConfigSession, Keys

# Предположим, у нас есть JWT токен, полученный извне
incoming_jwt_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLXV1aWQiLCJhdWQiOiJhcGkuZXhhbXBsZS5jb20iLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiXX0.abc123def456..."

# Конфигурация для валидации (только публичные ключи, без приватного)
config = ConfigSession(
    keys=keys,  # Экземпляр Keys с публичными ключами для верификации
    audience=["api.example.com"],  # Ожидаемая аудитория
    # header не нужен, так как он извлекается из токена
    # private_key не указан, так как нужна только верификация
)

try:
    # Создаем сессию для валидации
    validated_session = Session(config)
    
    # Валидируем и декодируем токен - это вызовет validate() внутри claims
    # При успехе claims будут автоматически установлены в сессию
    validated_session + incoming_jwt_token
    
    print(f"✅ Токен валиден")
    print(f"User ID: {validated_session.sub}")
    print(f"Audience: {validated_session.aud}")
    print(f"Scopes: {validated_session.scope}")
    print(f"Session ID: {validated_session.sid}")
    print(f"Expires at: {validated_session.exp}")  # UNIX timestamp
        
except InvalidClaimError as e:
    print(f"❌ Ошибка валидации claims: {e}")
except Exception as e:
    print(f"❌ Ошибка декодирования: {e}")
```

### Работа с JWE

```python
# Шифрование данных
header = {"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "encryption-key"}
encrypted_data = session.serialize("sensitive data", header)

# Дешифрование данных
decrypted_data = session.deserialize(encrypted_data)
print(f"Decrypted: {decrypted_data}")
```

## Структура проекта

```
xshl-session/
├── xshl/
│   └── session/
│       ├── __init__.py      # Основной модуль сессии
│       ├── claims.py        # Классы claims и валидация
│       └── keys.py          # Управление криптографическими ключами
├── requirements.txt
├── docs/
│   └──
├── LICENSE                     # GNU GPL v3 лицензия
└── COPYRIGHT                     # Копия лицензии GPL v3
```

## Детальная документация

### Класс Session

Основной класс для работы с JWT сессиями.

#### Свойства

- `iss` (str): Issuer claim
- `sub` (str): Subject claim (устанавливаемый)
- `aud` (str): Audience claim (устанавливаемый с валидацией)
- `sid` (str): Session ID
- `scope` (list): Список scope
- `path` (str): JWT location (опциональный)
- `response_type` (str): Response type (опциональный)
- `request_scope` (str): Request scope
- `payloads` (dict): Пользовательские данные
- `jwt` (str): Генерирует JWT токен

#### Методы

- `serialize(value, header)`: Шифрование данных через JWE
- `deserialize(value)`: Дешифрование JWE данных
- `update(**kwargs)`: Обновление нескольких свойств

### Класс ConfigSession

Конфигурация для создания сессии.

```python
ConfigSession(
    keys,           # Экземпляр Keys
    app=None,       # Application UUID
    audience=None,  # Разрешенные audience
    header=None,    # JWT headers
    version=1,      # Версия сессии
    expires=120,    # Время жизни в секундах
    key=None        # Приватный ключ
)
```

### Класс Keys

Управление криптографическими ключами.

```python
Keys(
    name,        # Имя набора ключей
    url,         # URL для загрузки JWKS
    ttl=60       # Время жизни кэша ключей
)
```

### Класс ReferenceKeys

Специализированный Keys для работы с XSHL Target.

```python
ReferenceKeys(
    target,      # XSHL Target объект
    trust_url,   # Базовый URL trust service
    ttl=60       # Время жизни кэша
)
```

## Расширенные примеры

### Кастомные claims

```python
from xshl.session import SessionClaims

class CustomClaims(SessionClaims):
    REGISTERED_CLAIMS = SessionClaims.REGISTERED_CLAIMS + ["custom_claim"]
    REQUIRED_CLAIMS = SessionClaims.REQUIRED_CLAIMS + ["custom_claim"]

# Использование кастомных claims
Session.claims_cls = CustomClaims
```

### Асинхронная загрузка ключей

```python
import asyncio

async def main():
    keys = Keys("my-keys", "https://keys.example.com/jwks.json")
    await keys._load()  # Явная асинхронная загрузка
    
    # Использование ключей
    key_set = keys()
    specific_key = keys("specific-kid")

asyncio.run(main())
```

### Интеграция с веб-фреймворком

```python
from flask import request, jsonify
from xshl.session import Session, ConfigSession

def create_session_endpoint():
    config = ConfigSession(...)
    
    try:
        session = Session(config)
        session + request.headers.get('Authorization', '').replace('Bearer ', '')
        
        # Проверка прав доступа
        if 'admin' not in session.scope:
            return jsonify({"error": "Insufficient permissions"}), 403
            
        return jsonify({"user": session.sub, "scopes": session.scope})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 401
```

## Конфигурация

### Переменные окружения

- `DEBUG=<Любое значение != 0>`: Включает debug logging (по умолчанию: 0)

### Логирование

Библиотека использует стандартный logging модуль Python:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Лицензия

GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007 - смотрите файлы [LICENSE](LICENSE) и [COPYING](COPYING) для деталей.

Это программное обеспечение распространяется под лицензией GPL v3, что означает:
- Вы можете использовать, изучать, изменять и распространять код
- Все производные работы должны распространяться под той же лицензией
- Вы должны предоставить исходный код производных работ

## Поддержка

Для багрепортов и feature requests создавайте issue на GitHub.

## Вклад в разработку

Приветствуются pull requests! Пожалуйста, убедитесь что:

1. Тесты проходят
2. Код соответствует PEP8
3. Добавлены соответствующие тесты для новых функций
4. Понимаете требования лицензии GPL v3 для вашего контрибуции

## Безопасность

Для report security vulnerabilities, пожалуйста, используйте security email вместо публичных issue.