import discord
from datetime import datetime, timedelta
from utils import format_cve_message
from cve_monitor import fetch_new_cves

PREFIX = "-"

async def message_handler(message):
    bot = message.guild.bot if hasattr(message.guild, "bot") else message.client
    if message.author == bot.user:
        return

    content = message.content.lower()

    # ---------- Comando: uptime ----------
    if content.startswith(f"{PREFIX}uptime"):
        delta = datetime.utcnow() - bot.uptime_start
        await message.channel.send(f"Bot ativo há {str(delta).split('.')[0]}")

    # ---------- Comando: pause ----------
    elif content.startswith(f"{PREFIX}pause"):
        bot.pause_reports = not bot.pause_reports
        status = "pausado" if bot.pause_reports else "ativado"
        await message.channel.send(f"Envio de reports {status}.")

    # ---------- Comando: clear ----------
    elif content.startswith(f"{PREFIX}clear"):
        await clear_messages(bot, message.channel)

    # ---------- Comando: critical-reports ----------
    elif content.startswith(f"{PREFIX}critical-reports"):
        await list_critical_reports(bot, message.channel)

    # ---------- Comando: new-reports ----------
    elif content.startswith(f"{PREFIX}new-reports"):
        await force_new_reports(bot, message.channel)

    # ---------- Comando: help ----------
    elif content.startswith(f"{PREFIX}help"):
        cmds = "-uptime\n-pause\n-clear\n-critical-reports\n-new-reports\n-help\n-return"
        await message.channel.send(f"Comandos disponíveis:\n{cmds}")

    # ---------- Comando: return ----------
    elif content.startswith(f"{PREFIX}return"):
        bot.pause_reports = False
        await message.channel.send("Bot retomou envio de reports.")

def register_message_commands(bot):
    """
    Registra o handler de mensagens apenas uma vez.
    """
    bot.add_listener(message_handler, "on_message")

# ---------- Funções auxiliares ----------
async def clear_messages(bot, channel):
    six_hours_ago = datetime.utcnow() - timedelta(hours=6)
    async for msg in channel.history(limit=200, after=six_hours_ago):
        if msg.author.bot and "@everyone" not in msg.content:
            try:
                await msg.delete()
            except:
                pass
    await channel.send("Mensagens não críticas removidas das últimas 6h.")

async def list_critical_reports(bot, channel):
    criticals = [cve for cve in bot.seen_db.values() if cve.get("critical")]
    if not criticals:
        await channel.send("Nenhuma CVE crítica ativa.")
        return
    msg = "**CVE(s) críticas atuais:**\n"
    for cve in criticals:
        msg += f"{cve['cve_id']} - {cve['asset']} - {cve['timestamp']}\n"
    await channel.send(msg)

async def force_new_reports(bot, channel):
    new_cves = await fetch_new_cves(bot.seen_db)
    if not new_cves:
        await channel.send("Nenhuma CVE nova encontrada no momento.")
        return
    for cve in new_cves:
        mention = "@everyone " if cve.get("critical") else ""
        await channel.send(mention + format_cve_message(cve))
