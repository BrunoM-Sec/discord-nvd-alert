import discord
from discord.ext import tasks
import datetime
import asyncio

# ---------- Configurações ----------
AUTO_CLEAN_INTERVAL = 6 * 60 + 20  # minutos -> 6h20min
PRESERVE_MINUTES = 20  # últimas 20 minutos de mensagens normais preservadas

@tasks.loop(minutes=1)
async def auto_cleanup(bot):
    """
    Executa limpeza automática de mensagens não críticas.
    - Só dispara após atingir AUTO_CLEAN_INTERVAL de uptime.
    - Preserva mensagens recentes (últimos PRESERVE_MINUTES minutos).
    - Mensagens críticas (contêm "CRITICAL") são mantidas.
    """
    now = datetime.datetime.utcnow()
    uptime_minutes = (now - bot.uptime_start).total_seconds() / 60

    if uptime_minutes < AUTO_CLEAN_INTERVAL:
        return  # Ainda não é hora de limpar

    channel = bot.get_channel(bot.channel_id)
    if channel is None:
        print("Canal não encontrado para auto-clean.")
        return

    try:
        async for message in channel.history(limit=500):
            # Ignora mensagens não do bot
            if message.author != bot.user:
                continue

            # Identifica mensagens críticas
            is_critical = "CRITICAL" in message.content.upper()
            age_minutes = (now - message.created_at).total_seconds() / 60

            # Deleta mensagens não críticas antigas
            if not is_critical and age_minutes > PRESERVE_MINUTES:
                try:
                    await message.delete()
                    await asyncio.sleep(0.3)  # evitar flood do Discord
                except discord.errors.Forbidden:
                    print("Sem permissão para deletar mensagem.")
                except discord.errors.HTTPException:
                    print("Erro HTTP ao deletar mensagem.")

        # Reset uptime para o próximo ciclo
        bot.uptime_start = now
        await channel.send("Auto-clean completo: mensagens antigas não críticas foram removidas.")
    
    except Exception as e:
        print(f"Erro no auto-clean: {e}")
