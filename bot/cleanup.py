import discord
from discord.ext import tasks
from datetime import datetime, timedelta
import asyncio

# Configurações do tempo
AUTO_CLEAN_INTERVAL_MINUTES = 6 * 60 + 20  # 6h20min
PRESERVE_MINUTES = 20  # preserva últimas 20 min de mensagens normais

@tasks.loop(minutes=1)
async def auto_cleanup(bot):
    """
    Limpa mensagens antigas não críticas a cada 6h20min.
    Preserva mensagens críticas e últimas 20 min.
    """
    now = datetime.utcnow()
    uptime_minutes = (now - bot.uptime_start).total_seconds() / 60

    if uptime_minutes < AUTO_CLEAN_INTERVAL_MINUTES:
        return  # ainda não é hora de limpar

    channel = bot.get_channel(bot.channel_id)
    if channel is None:
        print("Canal não encontrado para auto-clean")
        return

    try:
        async for message in channel.history(limit=500):
            # Mensagens críticas
            is_critical = "CRITICAL" in message.content.upper() or "@everyone" in message.content
            minutes_old = (now - message.created_at).total_seconds() / 60

            if not is_critical and minutes_old > PRESERVE_MINUTES:
                try:
                    await message.delete()
                    await asyncio.sleep(0.5)  # evita flood
                except discord.errors.Forbidden:
                    print("Sem permissão para deletar mensagem.")
                except discord.errors.HTTPException:
                    print("Erro HTTP ao deletar mensagem.")

        # Resetar uptime para contar próximo ciclo
        bot.uptime_start = now
        await channel.send("Auto-clean completo: mensagens antigas não críticas foram deletadas.")
    
    except Exception as e:
        print(f"Erro no auto-clean: {e}")
