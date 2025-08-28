import requests
import json
import os
import datetime
import discord
from discord.ext import commands, tasks

# -------------------------------
# CONFIGURAÇÕES DO BOT
# -------------------------------
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")   # Defina no ambiente (seguro)
CHANNEL_ID = int(os.getenv("DISCORD_CHANNEL_ID", "123456789"))  # Canal alvo
ASSETS = ["Windows 11", "Ubuntu", "Cisco", "Fortinet"]  # Ativos monitorados
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5"

# -------------------------------
# BOT DISCORD
# -------------------------------
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# Base simples para evitar alertas repetidos
DB_FILE = "seen_bd.json"
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump([], f)


def load_seen():
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_seen(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f)


# -------------------------------
# FUNÇÃO: Consulta CVEs na NVD
# -------------------------------
def fetch_nvd():
    try:
        resp = requests.get(NVD_API, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("vulnerabilities", [])
        return []
    except Exception as e:
        print(f"Erro ao consultar NVD: {e}")
        return []


# -------------------------------
# FUNÇÃO: Filtra ativos monitorados
# -------------------------------
def filter_assets(vulns):
    matched = []
    for v in vulns:
        cve = v.get("cve", {})
        descs = cve.get("descriptions", [])
        desc_text = " ".join(d["value"] for d in descs if "value" in d)
        for asset in ASSETS:
            if asset.lower() in desc_text.lower():
                matched.append({
                    "id": cve.get("id"),
                    "asset": asset,
                    "desc": desc_text[:200] + "...",  # corta p/ não ficar gigante
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}"
                })
    return matched


from datetime import datetime, timezone

async def cleanup_messages(channel):
    now = datetime.now(timezone.utc)  # datetime aware em UTC
    async for msg in channel.history(limit=50):
        if (now - msg.created_at).total_seconds() > 21600:  # 6h em segundos
            try:
                await msg.delete()
            except:
                pass




# -------------------------------
# FUNÇÃO: Envia alerta
# -------------------------------
async def send_alerts(channel, alerts):
    seen = load_seen()

    if alerts:
        for a in alerts:
            if a["id"] not in seen:
                msg = (
                    f"🚨 @everyone **Nova Vulnerabilidade Encontrada!** 🚨\n\n"
                    f"**CVE:** {a['id']}\n"
                    f"**Ativo:** {a['asset']}\n"
                    f"**Descrição:** {a['desc']}\n"
                    f"🔗 {a['url']}\n"
                    f"🕒 {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                )
                await channel.send(msg)
                seen.append(a["id"])
        save_seen(seen)
    else:
        # Nenhum alerta novo
        ativos = ", ".join(ASSETS)
        await channel.send(
            f"✅ Nenhuma nova vulnerabilidade encontrada.\n"
            f"Ativos monitorados: {ativos}\n"
            f"🕒 {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )


# -------------------------------
# LOOP AUTOMÁTICO
# -------------------------------
@tasks.loop(minutes=30)
async def check_nvd_task():
    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        await cleanup_messages(channel)  # limpa msgs antigas
        vulns = fetch_nvd()
        alerts = filter_assets(vulns)
        await send_alerts(channel, alerts)


@bot.event
async def on_ready():
    print(f"✅ Bot conectado como {bot.user}")
    check_nvd_task.start()


# -------------------------------
# INICIAR BOT
# -------------------------------
bot.run(DISCORD_TOKEN)
