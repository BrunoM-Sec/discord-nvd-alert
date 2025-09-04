import discord
from discord.ext import tasks, commands
import datetime
import os

from cve_monitor import fetch_new_cves
from cleanup import auto_cleanup
from commands import register_message_commands
from utils import load_seen_db, save_seen_db, format_cve_message
from config import CHANNEL_ID

TOKEN = os.getenv("DISCORD_BOT_TOKEN")
GUILD_ID = int(os.getenv("DISCORD_GUILD_ID"))

# Configurar intents
intents = discord.Intents.default()
intents.message_content = True
intents.messages = True

bot = commands.Bot(command_prefix="-", intents=intents)
bot.uptime_start = datetime.datetime.utcnow()
bot.pause_reports = False
bot.seen_db = load_seen_db("data/seen_db.json")
bot.channel_id = CHANNEL_ID

# ---------- Eventos Básicos ----------

@bot.event
async def on_ready():
    print(f"Bot conectado como {bot.user}")
    channel = bot.get_channel(bot.channel_id)
    await channel.send("Bot de Threat Intelligence iniciado e online.")
    await send_last_status(channel)
    monitor_cves.start()
    auto_cleanup.start(bot)
    register_message_commands(bot)

async def send_last_status(channel):
    """
    Envia relatório das últimas CVEs se o seen_db não estiver vazio.
    """
    if not bot.seen_db:
        await channel.send("Nenhuma CVE registrada ainda.")
        return

    msg = "**Status das últimas CVEs por ativo:**\n"
    for cve in bot.seen_db.values():
        msg += f"{cve['asset']}: {cve['cve_id']} publicada em {cve['timestamp']} - {cve['url']}\n"
    await channel.send(msg)

# ---------- Tarefa de Monitoramento ----------

@tasks.loop(minutes=60)
async def monitor_cves():
    if bot.pause_reports:
        return

    channel = bot.get_channel(bot.channel_id)
    new_cves = await fetch_new_cves(bot.seen_db)

    if new_cves:
        for cve in new_cves:
            mention = "@everyone " if cve.get("critical") else ""
            await channel.send(mention + format_cve_message(cve))
    else:
        # Caso não haja novas CVEs, enviar última CVE por ativo
        await send_last_status(channel)

# ---------- Rodando o bot ----------

bot.run(TOKEN)
