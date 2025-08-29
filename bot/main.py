import discord
from discord.ext import tasks, commands
import asyncio
import json
import datetime
import os

from cve_monitor import fetch_new_cves  # função que busca novas CVEs filtradas
from cleanup import auto_cleanup  # função de limpeza automática
from commands import register_commands  # registrar slash commands
from utils import load_seen_db, save_seen_db

TOKEN = os.getenv("DISCORD_BOT_TOKEN")  # coloque o token no seu ambiente
GUILD_ID = int(os.getenv("DISCORD_GUILD_ID"))  # servidor privado
CHANNEL_ID = int(os.getenv("DISCORD_CHANNEL_ID"))  # canal para enviar alertas

# Intents do bot
intents = discord.Intents.default()
intents.message_content = True
intents.messages = True

bot = commands.Bot(command_prefix="!", intents=intents)
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
    monitor_cves.start()
    register_commands(bot)
    auto_cleanup.start(bot)

# ---------- Tarefa de Monitoramento ----------

@tasks.loop(minutes=60)
async def monitor_cves():
    if bot.pause_reports:
        return

    channel = bot.get_channel(bot.channel_id)
    new_cves = await fetch_new_cves(bot.seen_db)
    
    for cve in new_cves:
        message = format_cve_message(cve)
        mention = ""
        if cve.get("critical") and cve.get("is_new"):
            mention = "@everyone "
        await channel.send(mention + message)

    save_seen_db(bot.seen_db, "data/seen_db.json")

# ---------- Função de formatação da mensagem ----------

def format_cve_message(cve):
    # Layout básico, você poderá aprimorar
    text = f"**{cve['cve_id']}**\n"
    text += f"Publicação: {cve['published_date']}\n"
    text += f"{cve['description']}\n"
    text += f"Link: {cve['url']}"
    return text

# ---------- Rodando o bot ----------

bot.run(TOKEN)

