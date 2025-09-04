import discord
from datetime import datetime, timedelta
from utils import format_cve_message
from cve_monitor import fetch_new_cves

# Prefixo do comando
PREFIX = "-"

def register_message_commands(bot):

    @bot.event
    async def on_message(message):
        # Ignora mensagens do próprio bot
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

# ---------- Funções auxiliares ----------

async def clear_messages(bot, channel):
    """
    Remove mensagens não críticas das últimas 6h.
    Nunca apaga mensagens com @everyone.
    """
    six_hours_ago = datetime.utcnow() - timedelta(hours=6)
    async for msg in channel.history(limit=200, after=six_hours_ago):
        if msg.author.bot and "@everyone" not in msg.content:
            try:
                await msg.delete()
                await discord.utils.sleep_until(datetime.utcnow() + timedelta(seconds=0.5))
            except discord.errors.Forbidden:
                print("Sem permissão para deletar mensagem.")
            except discord.errors.HTTPException:
                print("Erro HTTP ao deletar mensagem.")
    await channel.send("Mensagens não críticas removidas das últimas 6h.")

async def list_critical_reports(bot, channel):
    criticals = [cve for cve in bot.seen_db.values() if cve.get("critical")]
    if not criticals:
        await channel.send("Nenhuma CVE crítica ativa.")
        return
    msg = "**CVE(s) críticas atuais:**\n"
    for cve in criticals:
        msg += f"{cve['cve_id']} - {cve['asset']} - {cve['published_date']}\n"
    await channel.send(msg)

async def force_new_reports(bot, channel):
    """
    Força a consulta imediata de novas CVEs.
    """
    new_cves = await fetch_new_cves(bot.seen_db)
    if not new_cves:
        await channel.send("Nenhuma CVE nova encontrada no momento.")
        return

    for cve in new_cves:
        mention = "@everyone " if cve.get("critical") else ""
        await channel.send(mention + format_cve_message(cve))
