import discord
from discord.ext import tasks, commands
import asyncio
import datetime
import os

from cve_monitor import fetch_new_cves
from cleanup import auto_cleanup
from commands import register_message_commands
from utils import load_seen_db, save_seen_db

TOKEN = os.getenv("DISCORD_BOT_TOKEN")
CHANNEL_ID = int(os.getenv("DISCORD_CHANNEL_ID"))

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True

bot = commands.Bot(command_prefix="-", intents=intents)
bot.uptime_start = datetime.datetime.utcnow()
bot.pause_reports = False
bot.seen_db = load_seen_db("data/seen_db.json")
bot.channel_id = CHANNEL_ID

# ---------- Eventos ----------

@bot.event
async def on_ready():
    print(f"Bot conectado como {bot.user}")
    channel = await bot.fetch_channel(bot.channel_id)
    await channel.send("Bot de Threat Intelligence iniciado e online.")
    monitor_cves.start()
    register_message_commands(bot)
    auto_cleanup.start(bot)

# ---------- Monitoramento otimizado ----------

@tasks.loop(minutes=60)
async def monitor_cves():
    if bot.pause_reports:
        return

    channel = await bot.fetch_channel(bot.channel_id)
    
    # Tenta buscar CVEs até 3 vezes se falhar
    new_cves = []
    for attempt in range(3):
        try:
            new_cves = await fetch_new_cves(bot.seen_db)
            break
        except Exception as e:
            print(f"Erro ao buscar CVEs, tentativa {attempt+1}: {e}")
            await asyncio.sleep(5)
    
    if not new_cves:
        await channel.send("Nenhuma CVE nova encontrada nesta execução.")
        return

    # Agrupa mensagens para reduzir flood
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

# ---------- Função de formatação (opcional para comandos) ----------

def format_cve_message(cve):
    critical_tag = " (CRITICAL)" if cve.get("critical") else ""
    text = f"**{cve['cve_id']}**{critical_tag}\n"
    text += f"Ativo: {cve['asset']}\n"
    text += f"Publicação: {cve['published_date']}\n"
    text += f"{cve['description']}\n"
    text += f"Link: {cve['url']}"
    return text

bot.run(TOKEN)
