import discord
from datetime import datetime, timedelta
from utils import format_cve_message

PREFIX = "-"

def register_message_commands(bot):

    @bot.event
    async def on_message(message):
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
    Remove mensagens não críticas das últimas 6h
    """
    six_hours_ago = datetime.utcnow() - timedelta(hours=6)
    async for msg in channel.history(limit=500, after=six_hours_ago):
        if not msg.author.bot:
            continue
        if "CRITICAL" not in msg.content.upper():
            try:
                await msg.delete()
                await asyncio.sleep(0.3)
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
    msg = "CVE(s) críticas atuais:\n"
    for cve_id, data in bot.seen_db.items():
        if data.get("critical"):
            msg += f"{data['asset']} - {cve_id}\n"
    await channel.send(msg)

async def force_new_reports(bot, channel):
    """
    Executa uma busca imediata por novas CVEs, reportando no canal
    """
    from cve_monitor import fetch_new_cves
    new_cves = await fetch_new_cves(bot.seen_db)
    if not new_cves:
        # Exibir últimas CVEs caso não haja novas
        msg = "Nenhuma nova CVE encontrada.\nÚltimas CVEs conhecidas:\n"
        for cve_id, data in bot.seen_db.items():
            msg += f"{data['asset']} - {cve_id} (CRITICAL ⚠️)\n" if data.get("critical") else f"{data['asset']} - {cve_id}\n"
        await channel.send(msg)
        return

    for cve in new_cves:
        message = format_cve_message(cve)
        mention = "@everyone " if cve.get("critical") else ""
        await channel.send(mention + message)
