# Справочник API

Описание публичного API `xshl.session`.

## Модули
- `xshl.session` — примитивы сессии и вспомогательные функции
- `xshl.session.keys` — загрузка JWKS и поиск ключей
- `xshl.session.claims` — модель claims

## xshl.session

### Константы (фактические значения)
- `DEFAULT_SESSION_VERSION = 1` — версия сессии по умолчанию (встраивается в JWT)
- `DEFAULT_SESSION_EXPIRES = 120` — время жизни токена (сек)
- `DEFAULT_UID = "00000000-0000-0000-0000-000000000000"` — нулевой UUID-плейсхолдер
- `DEFAULT_STR = "undef"` — строковый плейсхолдер по умолчанию

### class JsonDumps
Назначение: временный контекстный менеджер для подмены `json.dumps` с кастомным `default`.
- Используется внутри `Session.jwt` для сериализации значений claims (например, `datetime`, `Target`), т.к. `authlib` не позволяет передать `default` в JSON дамп.
- Шаблон использования (внутренне): `with JsonDumps(): jwt.encode(...)
`.

### class Trace(*args)
Назначение: детерминированная трассировка запроса, привязанная к `jti`.
- `get(value: str) -> str`: детерминированный UUIDv5 из `jti` и аргументов трассировки.
- `validate(claims: JWTClaims, value: str) -> bool`: валидация claim `trace`.
- `__str__() -> str`: значения трассировки через двоеточие.

### class ConfigSession
Назначение: контейнер конфигурации для `Session` (ключи, приложение, заголовок, TTL и т.д.).
Конструктор:
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
- `keys: Keys`: провайдер JWKS.
- `app: str`: UUID издателя (строкой).
- `audience: list[str] | None`: список разрешённых аудиторий.
- `header: dict | None`: заголовок JWS/JWE, при указании должен содержать `kid`.
- `version: int`: версия сессии.
- `expires: int`: TTL токена в секундах.
- `private: Key | None`: приватный ключ для подписи/дешифрования.

### class Session
Назначение: высокоуровневая работа с JWT/JWE — управление claims и выпуск токенов.
Конструктор:
```python
Session(config: ConfigSession, *trace_args)
```
- `claims_cls`: переопределяемый класс claims, по умолчанию `SessionClaims`.
- `trace_cls`: переопределяемый класс трассировки, по умолчанию `Trace`.

Методы/интерфейс (оболочка над внутренним хранилищем `_claims`):
- `__add__(other: str) -> Session`: декодирует внешний JWT и мерджит выбранные claims.
- `__len__() -> int`: количество элементов во внутреннем `_claims`.
- `__contains__(key) -> bool`: проверка наличия ключа во внутреннем `_claims`.
- `__getitem__(key) -> Any`: доступ к значению claim из внутреннего `_claims`.
- `__iter__() -> Iterator[tuple[str, Any]]`: итерация по парам ключ/значение `_claims` (значения `None` пропускаются).
- `keys() -> KeysView[str]`: представление ключей `_claims` (удобно для `**session`).
- `update(**kwargs)`: групповые обновления с merge словарей.

Claims:
- `iss: str` (только чтение)
- `sub: str`
- `aud: str` (учитывает `ConfigSession.audience`)
- `sid: str` (только чтение)
- `scope: list[str]`
- `path: str | None` (`location`)
- `response_type: str | None` (`type`)
- `request_scope: str` (`_scope`)
- `payloads: dict` (`_payloads`)

JWT:
- `jwt -> str | None`: выпускает подписанный JWT, задаёт `jti`, `iat`, `nbf`, `exp`, `trace`. Внутри использует `JsonDumps` для сериализации в JSON.
- `options -> dict`: опции валидации (`version`, `sid`, `trace`, опционально `aud`).
- `name -> str`: `keys.name`.

JWE:
- `serialize(value: str | int | bytes, header: dict) -> str`: компактный JWE по публичному ключу `kid`.
- `deserialize(value: str | None) -> str | None`: дешифрование JWE приватным ключом.

## xshl.session.claims

### class SessionClaims(JWTClaims)
Назначение: наследник JWTClaims с обязательными полями и кастомной валидацией.
- `REGISTERED_CLAIMS`: стандартные + кастомные claims.
- `REQUIRED_CLAIMS`: помечаются как essential в `options`.
- `validate(now=None, leeway=0)`: расширяет базовую валидацию и проверяет значения кастомных claims.

## xshl.session.keys

### Константы
- `DEFAULT_KEYS_TTL = 60` — TTL обновления JWKS в секундах
- `API_REFERENCE = "/{version}/{source}/{path}{ext}?target={spot}:{entity}@{base}"` — шаблон пути, используемый `ReferenceKeys`

### class Keys
Назначение: загрузка и обновление JWKS; поиск ключей по `kid`.
Конструктор:
```python
Keys(name: str, url: str, ttl: int = DEFAULT_KEYS_TTL, verify_tls: bool = True)
```
- Первая загрузка — `requests` (синхронно). Фоновое обновление — `aiohttp`.
- `verify_tls=True` включает проверку TLS в обоих путях. Отключать `False` только в тестовых окружениях.

Методы/свойства:
- `load(background: bool = False) -> None`: Принудительное обновление ключей
- `updated -> bool`: Требуются ли обновление
- `__call__(kid: str | None) -> Key | KeySet | None`: Запрос всех ключе или поиск по `kid` если он передан

### class ReferenceKeys(Keys)
Назначение: специализированный `Keys`, формирующий JWKS URL из `Target`.
Конструктор:
```python
ReferenceKeys(target: Target, trust_url: str, ttl: int = DEFAULT_KEYS_TTL, verify_tls: bool = True)
```
- Формирует URL JWKS из метаданных `Target` и шаблона `API_REFERENCE`.

Хелпер:
- `api_path(item: dict) -> str`
