# py-xshl-session
Session in JWT 
=======================

[![PyPI version](https://img.shields.io/pypi/v/xshl-session.svg)](https://pypi.org/project/xshl-session/)
[![Python Version](https://img.shields.io/pypi/pyversions/xshl-session.svg)](https://pypi.org/project/xshl-session/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Библиотека для управления JWT/JWE сессиями с поддержкой криптографических ключей и интеграцией с XSHL Target system.

- 🇬🇧 English version: see `README.md`
- 📚 Полная документация: `docs/ru/index.md` → [Быстрый старт](docs/ru/quickstart.md), [Руководства](docs/ru/guides.md), [API](docs/ru/api.md), [Безопасность](docs/ru/security.md)

## Основные возможности

- 🔐 **JWT/JWE поддержка**: Полная поддержка JSON Web Tokens и JSON Web Encryption
- 🎯 **Интеграция с XSHL**: Работа с Target system для загрузки ключей
- ⚡ **Асинхронная загрузка**: Фоновая загрузка и автоматическое обновление ключей
- 🛡️ **Валидация claims**: Расширенная валидация claims с кастомными правилами
- 📦 **Сериализация/Десериализация**: Поддержка сериализации данных через JWE
- 🔍 **Трассировка**: Встроенная система трассировки запросов

## Константы
- `DEFAULT_SESSION_VERSION = 1`
- `DEFAULT_SESSION_EXPIRES = 120`
- `DEFAULT_UID = "00000000-0000-0000-0000-000000000000"`
- `DEFAULT_STR = "undef"`

## Быстрый старт

См. расширенную версию в `docs/ru/quickstart.md`.

```python
# ... пример см. в документации
```

Примечание: метод `Session.jwt` внутри использует контекстный менеджер `JsonDumps` для сериализации claims, поскольку `authlib` не предоставляет `default` для JSON дампа. Подробности см. в `docs/ru/api.md`.

## Документация

- Подробный API: `docs/ru/api.md`
- Руководства и эксплуатационные заметки: `docs/ru/guides.md`
- Безопасность: `docs/ru/security.md`

## Лицензия

GNU GPL v3 — см. [LICENSE](LICENSE) и [COPYRIGHT](COPYRIGHT).

## Вклад

- Issues/feature requests — GitHub
- Перед PR убедитесь:
  1. Тесты проходят
  2. Стиль и линтеры соблюдены
  3. Добавлены тесты для новых функций
  4. Понимаете требования GPL v3 к контрибуциям