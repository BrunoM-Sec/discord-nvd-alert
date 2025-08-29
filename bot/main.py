import discord
from discord.ext import tasks, commands
import asyncio
import datetime
import os

from cve_monitor import fetch_new_cves
from cleanup import auto_cleanup
from commands import register_message_commands
from utils import load_seen_db, save_seen_db, format_cve_message

TOKEN = os.getenv("DISCORD_BOT_TOKEN")
GUILD_ID = int(os.getenv("DISCORD_GUILD_ID"))
CHANNEL_ID = int(os.getenv("DISCORD_CHANNEL_ID"))

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True

bot = commands.Bot(command_prefix="!", intents=intents)
bot.uptime_start = datetime.datetime.utcnow()
bot.pause_reports = False
bot.seen_db = load_seen_db("data/seen_db.json")
bot.channel_id = CHANNEL_ID

# ---------- Eventos ----------

@bot.event
async def on_ready():
    print(f"Bot conectado como {bot.user}")
    channel = bot.get_channel(bot.channel_id)
    await channel.send("Bot de Threat Intelligence iniciado e online.")
    monitor_cves.start()
    auto_cleanup.start(bot)
    register_message_commands(bot)

# ---------- Tarefa de Monitoramento ----------

@tasks.loop(minutes=60)
async def monitor_cves():
    if bot.pause_reports:
        return

    channel = bot.get_channel(bot.channel_id)
    if channel is None:
        return

    new_cves = await fetch_new_cves(bot.seen_db)
    # Condição 1: novas CVEs críticas
    critical_sent = False
    for cve in new_cves:
        message = format_cve_message(cve)
        mention = "@everyone " if cve.get("critical") else ""
        await channel.send(mention + message)
        if cve.get("critical"):
            critical_sent = True

    # Condição 2: novas CVEs normais (não críticas)
    normal_cves = [cve for cve in new_cves if not cve.get("critical")]
    for cve in normal_cves:
        message = format_cve_message(cve)
        await channel.send(message)

    # Condição 3: nenhuma nova CVE encontrada
    if not new_cves:
        # Lista a última CVE conhecida por ativo
        msg = "Nenhuma nova CVE encontrada na última hora.\nÚltimas CVEs conhecidas:\n"
        for cve_id, data in bot.seen_db.items():
            msg += f"{data['asset']} - {cve_id} (CRITICAL ⚠️)\n" if data.get("critical") else f"{data['asset']} - {cve_id}\n"
        await channel.send(msg)

    # Salva estado atualizado
    save_seen_db(bot.seen_db, "data/seen_db.json")

# ---------- Rodando o bot ----------

bot.run(TOKEN)
