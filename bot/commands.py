import discord
from datetime import datetime, timedelta
from cve_monitor import fetch_new_cves
from utils import save_seen_db
import asyncio

PREFIX = "-"

def register_message_commands(bot):
    
    @bot.event
    async def on_message(message):
        if message.author == bot.user:
            return

        content = message.content.lower()

        if content.startswith(f"{PREFIX}uptime"):
            delta = datetime.utcnow() - bot.uptime_start
            await message.channel.send(f"Bot ativo há {str(delta).split('.')[0]}")

        elif content.startswith(f"{PREFIX}pause"):
            bot.pause_reports = not bot.pause_reports
            status = "pausado" if bot.pause_reports else "ativado"
            await message.channel.send(f"Envio de reports {status}.")

        elif content.startswith(f"{PREFIX}clear"):
            await clear_messages(bot, message.channel)

        elif content.startswith(f"{PREFIX}critical-reports"):
            await list_critical_reports(bot, message.channel)

        elif content.startswith(f"{PREFIX}new-reports"):
            await force_new_reports(bot, message.channel)

        await bot.process_commands(message)

# ---------- Funções auxiliares ----------

async def clear_messages(bot, channel):
    six_hours_ago = datetime.utcnow() - timedelta(hours=6)
    async for msg in channel.history(limit=500, after=six_hours_ago):
        if msg.author != bot.user:
            continue
        if "(CRITICAL)" not in msg.content:
            await msg.delete()
    await channel.send("Mensagens não críticas removidas das últimas 6h.")

async def list_critical_reports(bot, channel):
    criticals = [cve for cve in bot.seen_db.values() if cve.get("critical")]
    if not criticals:
        await channel.send("Nenhuma CVE crítica ativa.")
        return
    msg = "CVE(s) críticas atuais:\n"
    for cve in criticals:
        msg += f"{cve['cve_id']} - {cve['asset']}\n"
    await channel.send(msg)

async def force_new_reports(bot, channel):
    new_cves = []
    for attempt in range(3):
        try:
            new_cves = await fetch_new_cves(bot.seen_db)
            break
        except Exception as e:
            print(f"Erro ao buscar CVEs manualmente, tentativa {attempt+1}: {e}")
            await asyncio.sleep(5)

    if not new_cves:
        await channel.send("Nenhuma CVE nova encontrada.")
        return

    grouped_messages = {}
    for cve in new_cves:
        asset = cve['asset']
        grouped_messages.setdefault(asset, []).append(cve)

    for asset, cves in grouped_messages.items():
        message_lines = []
        mention = ""
        for cve in cves:
            critical_tag = " (CRITICAL)" if cve.get("critical") else ""
            message_lines.append(f"{cve['cve_id']}{critical_tag} - {cve['published_date']}")
            if cve.get("critical"):
                mention = "@everyone "
        message = f"**{asset}**\n" + "\n".join(message_lines)
        await channel.send(mention + message)

    save_seen_db(bot.seen_db, "data/seen_db.json")
