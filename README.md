# 🛡️ Justice Bot — Discord

**Белый хакер в кармане.** Бот для защиты от доксинга, сватинга и ДДоС-угроз: собирает доказательства с SHA-256, ищет нарушителя по открытым данным, проверяет уязвимости и оформляет жалобы по официальным каналам.

> ⚖️ Только легальные методы: публичные реестры, официальные API.

## Возможности

- 🔎 **OSINT**: `/osint username`, `/osint ip`, `/osint email`, `/osint password`
- 🕵️ **Полный скан**: `/scan` — карточка юзера + кейс с SHA-256
- 🛡️ **Watchlist**: `/watch add/remove/list/check` — мониторинг утечек email
- 📸 **Доказательства**: `/evidence snapshot/cases/verify` — с хешами
- 🚨 **Жалобы**: `/report template`, `/report links`
- 👁 **Авто-детект**: бот метит ⚠️ сообщения с признаками доксинга

## Быстрый старт

1. Скопируй `config.example.py` → `config.py`, впиши токен
2. `pip install -r requirements.txt`
3. `python bot.py`

## Структура

```
justice_bot/
├── bot.py          # Главный файл, команды
├── config.py       # Настройки (не заливай на GitHub!)
├── osint.py        # Поиск по открытым данным
├── evidence.py     # Доказательства с SHA-256
├── protector.py    # Watchlist утечек
└── reporter.py     # Шаблоны жалоб
```