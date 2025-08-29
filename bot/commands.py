import discord
from datetime import datetime, timedelta

# Prefixo do comando
PREFIX = "-"

def register_message_commands(bot):
    
    @bot.event
    async def on_message(message):
        # Ignora mensagens do próprio bot
        if message.author == bot.user:
            return
        
        # Comando -uptime
        if message.content.lower().startswith(f"{PREFIX}uptime"):
            delta = datetime.utcnow() - bot.uptime_start
            await message.channel.send(f"Bot ativo há {str(delta).split('.')[0]}")
        
        # Comando -pause
        elif message.content.lower().startswith(f"{PREFIX}pause"):
            bot.pause_reports = not bot.pause_reports
            status = "pausado" if bot.pause_reports else "ativado"
            await message.channel.send(f"Envio de reports {status}.")
        
        # Comando -clear
        elif message.content.lower().startswith(f"{PREFIX}clear"):
            await clear_messages(bot, message.channel)
        
        # Comando -critical-reports
        elif message.content.lower().startswith(f"{PREFIX}critical-reports"):
            await list_critical_reports(bot, message.channel)
        
        # Comando -new-reports
        elif message.content.lower().startswith(f"{PREFIX}new-reports"):
            await force_new_reports(bot, message.channel)

# Funções auxiliares

async def clear_messages(bot, channel):
    """
    Remove mensagens não críticas das últimas 6h
    """
    six_hours_ago = datetime.utcnow() - timedelta(hours=6)
    async for msg in channel.history(limit=200, after=six_hours_ago):
        if not msg.author.bot:
            continue
        if "CRITICAL" not in msg.content.upper():
            await msg.delete()
    await channel.send("Mensagens não críticas removidas das últimas 6h.")

async def list_critical_reports(bot, channel):
    criticals = [cve for cve in bot.seen_db.values() if cve.get("critical")]
    if not criticals:
        await channel.send("Nenhuma CVE crítica ativa.")
        return
    msg = "CVE(s) críticas atuais:\n"
    for cve in criticals:
        msg += f"{cve['id']} - {cve['ativo']}\n"
    await channel.send(msg)

async def force_new_reports(bot, channel):
    from cve_monitor import fetch_new_cves
    new_cves = await fetch_new_cves(bot.seen_db)
    if not new_cves:
        await channel.send("Nenhuma CVE nova encontrada.")
        return
    for cve in new_cves:
        await channel.send(f"{cve['ativo']} - {cve['id']} (CRITICAL)" if cve.get("critical") else f"{cve['ativo']} - {cve['id']}")
