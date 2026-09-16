import json
import os
from datetime import datetime

import config
from osint import breach_check

# ================= Защита от доксинга =================
# Watchlist эмейлов -> периодическая проверка утечек.
# При новом инциденте шлём алерт в канал.

WATCH_FILE = "watchlist.json"


def load_watchlist() -> dict:
    if os.path.exists(WATCH_FILE):
        with open(WATCH_FILE, encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_watchlist(data: dict):
    with open(WATCH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def is_watching(email: str) -> bool:
    return email.lower() in {k.lower() for k in load_watchlist()}


def add_watch(email: str, owner_note: str = "") -> dict:
    data = load_watchlist()
    key = email.lower()
    if key in data:
        return {"added": False, "email": email}
    data[key] = {
        "email": email,
        "note": owner_note,
        "added_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "known_breaches": [],
    }
    save_watchlist(data)
    return {"added": True, "email": email}


def remove_watch(email: str) -> bool:
    data = load_watchlist()
    key = email.lower()
    if key in data:
        del data[key]
        save_watchlist(data)
        return True
    return False


def check_watchlist(api_key: str = "") -> list:
    """Проверяет все эмейлы; возвращает список новых утечек."""
    data = load_watchlist()
    alerts = []
    for key, item in data.items():
        breaches = breach_check(item["email"], api_key)
        if not isinstance(breaches, list) or not breaches:
            continue
        known = set(item.get("known_breaches", []))
        new = [b for b in breaches if b not in known]
        if new:
            item["known_breaches"] = breaches
            alerts.append({"email": item["email"], "note": item.get("note", ""), "new": new})
    if alerts:
        save_watchlist(data)
    return alerts