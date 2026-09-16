import asyncio
import logging

import discord
from discord import app_commands

import config
import evidence
import osint
import protector
import reporter

logging.basicConfig(level=logging.INFO)

# ---------- Интенты ----------
intents = discord.Intents.default()
intents.message_content = True
intents.messages = True


class JusticeBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        self.loop.create_task(watch_background())
        try:
            await self.tree.sync()
            logging.info("Слэш-команды синхронизированы")
        except Exception as e:
            logging.error(f"Синхронизация: {e}")

    async def on_ready(self):
        logging.info(f"Бот запущен: {self.user}")


client = JusticeBot()


def is_owner(interaction) -> bool:
    return interaction.user.id == config.OWNER_ID


async def owner_only(interaction) -> bool:
    if interaction.user.id == config.OWNER_ID:
        return True
    await interaction.response.send_message("⛔ Только владелец бота!", ephemeral=True)
    return False


def check_owner(interaction) -> bool:
    if interaction.user.id == config.OWNER_ID:
        return True
    return False


# ================= OSINT-команды =================

osc = app_commands.Group(name="osint", description="Легальные OSINT-проверки")


@osc.command(name="username", description="Ищем ник на публичных платформах")
@app_commands.describe(username="Никнейм для поиска")
async def osint_username(interaction: discord.Interaction, username: str):
    if not check_owner(interaction):
        return
    await interaction.response.defer(thinking=True)
    results = osint.check_username(username)
    lines = [f"🔎 Ник: **{username}**"]
    for name, status, url in results:
        mark = {"НАЙДЕН": "✅", "Свободен": "⬜"}.get(status, "❔")
        lines.append(f"{mark} **{name}** — {status}")
    await interaction.followup.send("\n".join(lines))


@osc.command(name="ip", description="Информация по IP (открытые реестры)")
@app_commands.describe(ip="IP-адрес")
async def osint_ip(interaction: discord.Interaction, ip: str):
    if not check_owner(interaction):
        return
    await interaction.response.defer(thinking=True)
    data = osint.lookup_ip(ip)
    if "error" in data:
        await interaction.followup.send(f"❌ {data['error']}")
        return
    text = (
        f"🌐 **{data.get('query')}**\n"
        f"📍 {data.get('city', '?')}, {data.get('regionName', '?')}, {data.get('country', '?')}\n"
        f"🏢 Провайдер: {data.get('isp', '?')}\n"
        f"🕸 Организация: {data.get('org', '?')}\n"
        f"🛰 AS: {data.get('as', '?')}\n"
        f"✅ Данные из публичных реестров (ip-api.com)"
    )
    await interaction.followup.send(text)


@osc.command(name="email", description="Проверка email по базе утечек (HIBP)")
@app_commands.describe(email="Email-адрес")
async def osint_email(interaction: discord.Interaction, email: str):
    if not check_owner(interaction):
        return
    await interaction.response.defer(thinking=True)
    if not config.HIBP_API_KEY:
        await interaction.followup.send(
            "Нужен ключ HIBP (бесплатный). Впиши в config.py: https://haveibeenpwned.com/API/Key"
        )
        return
    breaches = osint.breach_check(email, config.HIBP_API_KEY)
    if breaches and isinstance(breaches[0], dict) and "error" in breaches[0]:
        await interaction.followup.send(f"❌ {breaches[0]['error']}")
        return
    if breaches:
        await interaction.followup.send(
            f"⚠️ Email **{email}** найден в утечках:\n" + "\n".join(f"- {b}" for b in breaches)
        )
    else:
        await interaction.followup.send(f"✅ Утечек по **{email}** не найдено")


@osc.command(name="password", description="Проверка пароля по утечкам (бесплатный API)")
@app_commands.describe(password="Пароль для проверки (не сохраняется)")
async def osint_pass(interaction: discord.Interaction, password: str):
    if not check_owner(interaction):
        return
    await interaction.response.defer(thinking=True)
    res = osint.password_breached(password)
    if res["pwned"]:
        await interaction.followup.send(
            f"🚨 Пароль встречался в утечках **{res['count']}** раз. Срочно смени!"
        )
    else:
        await interaction.followup.send("✅ Пароль в публичных утечках не найден")


# ================= Защита от доксинга =================

prot = app_commands.Group(name="watch", description="Watchlist для защиты от утечек")


@prot.command(name="add", description="Добавить email под наблюдение")
@app_commands.describe(email="Email для мониторинга", note="Кому принадлежит (например Оля)")
async def watch_add(interaction: discord.Interaction, email: str, note: str = ""):
    if not check_owner(interaction):
        return
    await interaction.response.defer(thinking=True)
    res = protector.add_watch(email, note)
    if res["added"]:
        await interaction.followup.send(f"✅ **{email}** добавлен в watchlist")
    else:
        await interaction.followup.send(f"ℹ️ **{email}** уже в watchlist")


@prot.command(name="remove", description="Убрать email из watchlist")
@app_commands.describe(email="Email для удаления")
async def watch_remove(interaction: discord.Interaction, email: str):
    if not check_owner(interaction):
        return
    ok = protector.remove_watch(email)
    await interaction.response.send_message(
        f"✅ Удалён: {email}" if ok else f"❌ Не в списке: {email}"
    )


@prot.command(name="list", description="Показать всё, что под наблюдением")
async def watch_list(interaction: discord.Interaction):
    if not check_owner(interaction):
        return
    data = protector.load_watchlist()
    if not data:
        await interaction.response.send_message("Пусто. Добавь через /watch add")
        return
    lines = ["📋 Watchlist:"]
    for item in data.values():
        known = ", ".join(item.get("known_breaches", [])) or "—"
        lines.append(f"- {item['email']} ({item.get('note', '?')}) — найдено: {known}")
    await interaction.response.send_message("\n".join(lines))


# ================= Сбор доказательств =================

ev = app_commands.Group(name="evidence", description="Доказательства с SHA-256 хешами")


@ev.command(name="snapshot", description="Снять срез сообщений пользователя")
@app_commands.describe(user="Кого зафиксировать (mention)")
async def ev_snapshot(interaction: discord.Interaction, user: discord.Member):
    if not check_owner(interaction):
        return
    await interaction.response.defer(thinking=True)
    msgs = []
    async for m in interaction.channel.history(limit=200):
        if m.author.id == user.id and m.content:
            msgs.append(m)
        if len(msgs) >= 50:
            break
    rec = evidence.snapshot_user(user.display_name, user.id, msgs)
    await interaction.followup.send(
        f"📸 Зафиксировано {rec['meta']['messages']} сообщений от **{user.display_name}**\n"
        f"Кейс: `{rec['case']}`\n"
        f"SHA-256: `{rec['sha256']}`\n"
        f"Время: `{rec['saved_at']}`"
    )


@ev.command(name="cases", description="Список сохранённых кейсов")
async def ev_cases(interaction: discord.Interaction):
    if not check_owner(interaction):
        return
    cases = evidence.list_cases()
    if not cases:
        await interaction.response.send_message("Кейсов пока нет")
        return
    lines = [f"📁 {len(cases)} кейс(ов):"]
    for c in cases[:10]:
        lines.append(f"- `{c['case']}` | {c['meta'].get('target_name', '?')} | {c['meta']['messages']} msg")
    await interaction.response.send_message("\n".join(lines))


@ev.command(name="verify", description="Проверить целостность кейса")
@app_commands.describe(case_id="ID кейса")
async def ev_verify(interaction: discord.Interaction, case_id: str):
    if not check_owner(interaction):
        return
    res = evidence.verify_case(case_id)
    if res["ok"]:
        await interaction.response.send_message(f"✅ Кейс `{case_id}` не изменён. Хеш совпадает.")
    else:
        await interaction.response.send_message(
            f"❌ {res.get('reason', 'Кейс изменён!')}\nБыло: {res.get('recorded')}\nСтало: {res.get('current')}"
        )


# ================= Авто-репорт =================

rp = app_commands.Group(name="report", description="Жалобы по официальным каналам")


@rp.command(name="template", description="Сгенерировать жалобу для платформы")
@app_commands.describe(platform="Платформа", link="Ссылка на нарушение/профиль", details="Что произошло", proof="Доказательства (кейс/скриншот)")
async def rp_template(interaction: discord.Interaction, platform: str, link: str, details: str, proof: str = ""):
    if not check_owner(interaction):
        return
    await interaction.response.defer(thinking=True)
    await interaction.followup.send(reporter.report_template(platform.capitalize(), link, proof, details))


@rp.command(name="links", description="Официальные ссылки для репортов")
async def rp_links(interaction: discord.Interaction):
    if not check_owner(interaction):
        return
    lines = ["📮 Официальные каналы жалоб:"]
    for name, url in reporter.REPORT_LINKS.items():
        lines.append(f"- **{name}**: {url}")
    await interaction.response.send_message("\n".join(lines))


# ================= Регистрация групп =================

for group in (osc, prot, ev, rp):
    client.tree.add_command(group)


@client.tree.command(name="scan", description="Проверить юзера по OSINT + сохранить кейс")
@app_commands.describe(user="Кого проверить", ip="Его IP (если известен)")
async def scan(interaction: discord.Interaction, user: discord.Member, ip: str = None):
    if not check_owner(interaction):
        return
    await interaction.response.defer(thinking=True)

    msgs = []
    async for m in interaction.channel.history(limit=300):
        if m.author.id == user.id and m.content:
            msgs.append(m)
        if len(msgs) >= 50:
            break
    rec = evidence.snapshot_user(user.display_name, user.id, msgs)

    parts = [
        f"🎯 **{user.display_name}**",
        f"ID: `{user.id}`",
        f"Кейс: `{rec['case']}`  SHA-256: `{rec['sha256'][:16]}…`",
    ]
    if ip:
        data = osint.lookup_ip(ip)
        if "error" not in data:
            parts.append(
                f"📍 {data.get('city', '?')}, {data.get('country', '?')} | {data.get('isp', '?')}"
            )

    found = osint.check_username(user.display_name.replace(" ", ""))[:6]
    present = [name for name, st, url in found if st == "НАЙДЕН"]
    if present:
        parts.append("🕵️ Активен на: " + ", ".join(present))

    await interaction.followup.send("\n".join(parts))


# ================= Авто-детект опасных слов (только метка) =================

@client.event
async def on_message(message):
    if message.author.bot:
        return
    if isinstance(message.channel, discord.DMChannel):
        return
    low = message.content.lower()
    if any(w in low for w in config.DANGER_WORDS):
        logging.warning(f"[DANGER] {message.author} | {message.content[:120]}")
        try:
            await message.add_reaction("⚠️")
        except Exception:
            pass


# ================= Фоновый мониторинг watchlist =================

async def watch_background():
    await client.wait_until_ready()
    while not client.is_closed():
        await asyncio.sleep(config.WATCH_INTERVAL_HOURS * 3600)
        if not config.HIBP_API_KEY or not config.ALERT_CHANNEL_ID:
            continue
        try:
            alerts = protector.check_watchlist(config.HIBP_API_KEY)
        except Exception as e:
            logging.error(f"watch: {e}")
            continue
        chan = client.get_channel(config.ALERT_CHANNEL_ID)
        if not chan:
            continue
        for a in alerts:
            try:
                await chan.send(f"🚨 **{a['email']}** ({a['note']}) — НОВЫЕ утечки: {', '.join(a['new'])}")
            except Exception as e:
                logging.error(e)


# ================= Запуск =================

def main():
    if config.BOT_TOKEN.startswith("ВСТАВЬ"):
        print("⚠️  Сначала впиши BOT_TOKEN и OWNER_ID в config.py!")
        return
    client.run(config.BOT_TOKEN)


if __name__ == "__main__":
    main()