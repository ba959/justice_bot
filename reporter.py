# ================= Авто-репорт =================
# Формирует официальные ссылки и шаблоны жалоб в поддержку платформ.
# Всё это — легальные способы сообщить о нарушителе модерации.

REPORT_LINKS = {
    "Discord": "https://dis.gd/request (Анкета в поддержку Discord)",
    "Telegram": "https://telegram.org/support (Написать в поддержку)",
    "Twitter/X": "https://help.twitter.com/forms/abusive",
    "Instagram": "https://help.instagram.com/contact/692198749110837",
    "Reddit": "https://www.reddit.com/report",
    "YouTube": "https://support.google.com/youtube/answer/2802027",
    "Twitch": "https://help.twitch.tv/s/contactsupport",
    "Steam": "https://help.steampowered.com/",
    "GitHub": "https://github.com/contact/report-abuse",
}

SERVER_POLICE = ("101", "102")


def report_template(platform: str, link: str, proof: str, details: str) -> str:
    return (
        f"=== ЖАЛОБА: {platform} ===\n"
        f"1. Что произошло:\n{details}\n\n"
        f"2. Ссылка на нарушение:\n{link}\n\n"
        f"3. Доказательства (кейс/скриншоты):\n{proof or '(приложите хеш кейса)'}\n\n"
        f"4. По какому пункту правил:\n"
        f"- разглашение персональных данных (доксинг)\n"
        f"- призывы к насилию / угрозы\n"
        f"- фальшивые вызовы экстренных служб (сватинг)\n\n"
        f"Отправлено через {platform} -> ссылка репорта: {REPORT_LINKS.get(platform, platform)}\n"
        f"Копия сохранена. Не вступайте в перепалку, только факты."
    )