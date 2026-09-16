import hashlib
import json
import os
from datetime import datetime

import config

# ================= Сбор доказательств =================
# Каждое доказательство хранится с SHA-256 хешем и временем,
# чтобы показать, что файл не меняли (юридически корректно).


def ensure_dir():
    os.makedirs(config.EVIDENCE_DIR, exist_ok=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_case(case_id: str, meta: dict, body: str) -> dict:
    """Сохраняет текстовое доказательство в case-папку."""
    ensure_dir()
    case_dir = os.path.join(config.EVIDENCE_DIR, case_id)
    os.makedirs(case_dir, exist_ok=True)

    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    body_b = body.encode("utf-8")
    hash_val = sha256(body_b)

    record = {
        "case": case_id,
        "saved_at": ts,
        "sha256": hash_val,
        "size": len(body_b),
        "meta": meta,
    }

    with open(os.path.join(case_dir, "record.json"), "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
    with open(os.path.join(case_dir, "evidence.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(body)

    return record


def snapshot_user(user_name: str, user_id: int, msgs: list) -> dict:
    """Делает срез сообщений пользователя (доказательство)."""
    lines = []
    for m in msgs:
        lines.append(f"[{m.created_at.isoformat(timespec='seconds')}] {m.author}: {m.content}")
    body = "\n".join(lines) or "(пусто)"
    meta = {"target_name": user_name, "target_id": user_id, "messages": len(lines)}
    case_id = f"user_{user_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    return save_case(case_id, meta, body)


def list_cases() -> list:
    """Список сохранённых кейсов."""
    ensure_dir()
    out = []
    for name in os.listdir(config.EVIDENCE_DIR):
        rec = os.path.join(config.EVIDENCE_DIR, name, "record.json")
        if os.path.exists(rec):
            with open(rec, encoding="utf-8") as f:
                out.append(json.load(f))
    return sorted(out, key=lambda r: r.get("saved_at", ""), reverse=True)


def verify_case(case_id: str) -> dict:
    """Проверяет целостность кейса (подходит ли текущий хеш)."""
    path = os.path.join(config.EVIDENCE_DIR, case_id, "evidence.txt")
    if not os.path.exists(path):
        return {"ok": False, "reason": "Кейс не найден"}
    with open(path, "rb") as f:
        cur = sha256(f.read())
    with open(os.path.join(config.EVIDENCE_DIR, case_id, "record.json"), encoding="utf-8") as f:
        rec = json.load(f)
    return {"ok": cur == rec["sha256"], "recorded": rec["sha256"], "current": cur}