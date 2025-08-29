import discord
from discord.ext import tasks
import datetime
import asyncio

# Configurações do tempo
AUTO_CLEAN_INTERVAL = 6 * 60 + 20  # minutos -> 6h20min
PRESERVE_MINUTES = 20  # últimas 20 min de mensagens normais

@tasks.loop(minutes=1)
async def auto_cleanup(bot):
    """
    Verifica se o bot atingiu o tempo de auto-clean (6h20min).
    Se sim, deleta mensagens não críticas antigas e preserva últimas 20 min.
    """
    now = datetime.datetime.utcnow()
    uptime = (now - bot.uptime_start).total_seconds() / 60  # em minutos

    if uptime < AUTO_CLEAN_INTERVAL:
        return  # ainda não é hora de limpar

    channel = bot.get_channel(bot.channel_id)
    if channel is None:
        return

    try:
        # Buscar mensagens recentes (até limite do Discord)
        async for message in channel.history(limit=500):
            # Não deletar mensagens críticas (contêm "critical": True na embed ou json)
            is_critical = "CRITICAL" in message.content.upper()
            message_time = message.created_at
            minutes_old = (now - message_time).total_seconds() / 60

            # Se mensagem não é crítica e é mais antiga que PRESERVE_MINUTES, deletar
            if not is_critical and minutes_old > PRESERVE_MINUTES:
                try:
                    await message.delete()
                    await asyncio.sleep(0.5)  # evitar flood
                except discord.errors.Forbidden:
                    print("Sem permissão para deletar mensagem.")
                except discord.errors.HTTPException:
                    print("Erro HTTP ao deletar mensagem.")

        # Resetar uptime para contar próximo ciclo
        bot.uptime_start = now
        await channel.send("Auto-clean completo: mensagens antigas não críticas foram deletadas.")
    
    except Exception as e:
        print(f"Erro no auto-clean: {e}")


