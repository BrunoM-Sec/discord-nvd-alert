import discord
from discord.ext import tasks
from datetime import datetime, timedelta
import asyncio
from utils import format_cve_message

# ---------- Configurações ----------
AUTO_CLEAN_INTERVAL_MIN = 6 * 60 + 20  # 6h20min em minutos
PRESERVE_WINDOW_MIN = 60  # preserva mensagens normais recentes (1 hora)

# ---------- Loop de limpeza ----------
@tasks.loop(minutes=1)
async def auto_cleanup(bot):
    """
    Executa limpeza automática de mensagens não críticas.
    Preserva mensagens recentes e críticas.
    """
    now = datetime.utcnow()
    
    # Inicializa last_cleanup se não existir
    if not hasattr(bot, "last_cleanup"):
        bot.last_cleanup = bot.uptime_start

    # Checa se já passou o intervalo
    minutes_since_last = (now - bot.last_cleanup).total_seconds() / 60
    if minutes_since_last < AUTO_CLEAN_INTERVAL_MIN:
        return  # ainda não é hora de limpar

    channel = bot.get_channel(bot.channel_id)
    if channel is None:
        print("[WARN] Canal não encontrado para cleanup.")
        return

    try:
        async for message in channel.history(limit=500, after=now - timedelta(hours=6)):
            # Considera mensagem crítica se contém [CRITICAL]
            is_critical = "[CRITICAL]" in message.content.upper()
            
            message_age_min = (now - message.created_at).total_seconds() / 60
            
            if not is_critical and message_age_min > PRESERVE_WINDOW_MIN:
                try:
                    await message.delete()
                    await asyncio.sleep(0.5)  # evitar flood
                except discord.errors.Forbidden:
                    print("[ERROR] Sem permissão para deletar mensagem.")
                except discord.errors.HTTPException as e:
                    print(f"[ERROR] Erro HTTP ao deletar mensagem: {e}")

        bot.last_cleanup = now
        await channel.send("Auto-clean completo: mensagens antigas não críticas foram deletadas.")

    except Exception as e:
        print(f"[ERROR] Erro no auto-clean: {e}")
