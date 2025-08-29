import discord
from discord.ext import commands, tasks
import datetime
import asyncio

from cve_monitor import fetch_new_cves
from cleanup import auto_cleanup
from utils import save_seen_db

def register_commands(bot):
    guild_id = bot.get_guild(bot.guilds[0].id)  # usar o primeiro servidor do bot

    @bot.tree.command(name="clear", description="Limpa últimas 6h de mensagens não críticas")
    async def clear(interaction: discord.Interaction):
        await interaction.response.send_message("Iniciando limpeza manual de mensagens não críticas...", ephemeral=True)
        await manual_clear(bot)
        await interaction.followup.send("Limpeza manual concluída.", ephemeral=True)

    @bot.tree.command(name="pause", description="Pausa ou retoma o envio de reports automáticos")
    async def pause(interaction: discord.Interaction):
        bot.pause_reports = not bot.pause_reports
        status = "pausado" if bot.pause_reports else "ativo"
        await interaction.response.send_message(f"Relatórios automáticos agora estão {status}.", ephemeral=True)

    @bot.tree.command(name="uptime", description="Mostra o tempo que o bot está ativo")
    async def uptime(interaction: discord.Interaction):
        now = datetime.datetime.utcnow()
        uptime_minutes = int((now - bot.uptime_start).total_seconds() / 60)
        hours = uptime_minutes // 60
        minutes = uptime_minutes % 60
        await interaction.response.send_message(f"Bot está ativo há {hours}h {minutes}min.", ephemeral=True)

    @bot.tree.command(name="critical-reports", description="Lista alertas críticos ativos")
    async def critical_reports(interaction: discord.Interaction):
        criticals = [cve for cve in bot.seen_db.values() if cve.get("critical")]
        if not criticals:
            await interaction.response.send_message("Não há alertas críticos ativos.", ephemeral=True)
        else:
            msg = "**Alertas Críticos Ativos:**\n"
            for c in criticals:
                msg += f"{c['asset']} - {c['timestamp']}\n"
            await interaction.response.send_message(msg, ephemeral=True)

    @bot.tree.command(name="new-reports", description="Força uma nova consulta às APIs de CVE")
    async def new_reports(interaction: discord.Interaction):
        await interaction.response.send_message("Consultando CVEs mais recentes...", ephemeral=True)
        new_cves = await fetch_new_cves(bot.seen_db)
        channel = bot.get_channel(bot.channel_id)
        for cve in new_cves:
            message = f"**{cve['cve_id']}**\nPublicação: {cve['published_date']}\n{cve['description']}\nLink: {cve['url']}"
            mention = "@everyone " if cve.get("critical") and cve.get("is_new") else ""
            await channel.send(mention + message)
        save_seen_db(bot.seen_db, "data/seen_db.json")
        await interaction.followup.send("Nova consulta concluída e mensagens enviadas.", ephemeral=True)


# ---------- Função auxiliar de limpeza manual ----------
async def manual_clear(bot):
    now = datetime.datetime.utcnow()
    channel = bot.get_channel(bot.channel_id)
    if channel is None:
        return

    async for message in channel.history(limit=500):
        is_critical = "CRITICAL" in message.content.upper()
        message_time = message.created_at
        minutes_old = (now - message_time).total_seconds() / 60

        if not is_critical and minutes_old <= 360:  # últimas 6h
            try:
                await message.delete()
                await asyncio.sleep(0.5)
            except discord.errors.Forbidden:
                print("Sem permissão para deletar mensagem.")
            except discord.errors.HTTPException:
                print("Erro HTTP ao deletar mensagem.")

