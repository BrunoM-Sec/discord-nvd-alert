import requests
import json
import os
from datetime import datetime, timezone
import discord
from discord.ext import commands, tasks

# -------------------------------
# CONFIGURAÇÕES DO BOT
# -------------------------------
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
CHANNEL_ID = int(os.getenv("DISCORD_CHANNEL_ID", "123456789"))
ASSETS = [
    "Red Hat Enterprise Linux 9",
    "Oracle Database 19c",
    "Juniper MX Series",
    "Ubuntu 22.04 LTS",
    "Mozila Firefox"
]
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50"

# -------------------------------
# BOT DISCORD
# -------------------------------
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# Arquivo JSON para armazenar CVEs já notificadas
DB_FILE = "seen_bd.json"
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump([], f)


def load_seen():
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_seen(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


# -------------------------------
# CONSULTA CVEs NVD
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
# FILTRA ATIVOS E PEGA A ÚLTIMA CVE POR ATIVO
# -------------------------------
def filter_assets_last(vulns):
    matched = {asset: None for asset in ASSETS}

    for v in vulns:
        cve = v.get("cve", {})
        descs = cve.get("descriptions", [])
        desc_text = " ".join(d["value"] for d in descs if "value" in d)
        cve_id = cve.get("id")
        published = cve.get("published", "N/A")

        for asset in ASSETS:
            if asset.lower() in desc_text.lower():
                if matched[asset] is None or published > matched[asset]["published"]:
                    matched[asset] = {
                        "id": cve_id,
                        "desc": desc_text[:200] + "...",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "published": published
                    }
    return matched


# -------------------------------
# LIMPA MENSAGENS ANTIGAS (>6h)
# -------------------------------
async def cleanup_messages(channel):
    now = datetime.now(timezone.utc)
    async for msg in channel.history(limit=50):
        if "Nova Vulnerabilidade" not in msg.content:
            if (now - msg.created_at).total_seconds() > 21600:
                try:
                    await msg.delete()
                except:
                    pass


# -------------------------------
# ENVIA ALERTA NO DISCORD (LAYOUT POR ATIVO)
# -------------------------------
async def send_alerts(channel, alerts):
    seen = load_seen()
    any_new = False
    message_lines = ["🚨 @everyone **Nova Vulnerabilidade Encontrada!** 🚨\n"]

    for asset, cve in alerts.items():
        if cve:
            # registra no JSON apenas se CVE nova
            if cve["id"] not in seen:
                seen.append(cve["id"])
                any_new = True
            # formata data/hora UTC para exibição
            try:
                dt = datetime.fromisoformat(cve["published"].replace("Z", "+00:00"))
                published_str = dt.strftime("%Y-%m-%d / %H:%M UTC")
            except:
                published_str = cve["published"]

            # adiciona ao corpo da mensagem
            message_lines.append(f"┏ {asset} ┓")
            message_lines.append(f"{cve['id']} / {published_str}")
            message_lines.append(f"🔗 {cve['url']}\n")

    save_seen(seen)

    if any_new:
        await channel.send("\n".join(message_lines))
    else:
        # Mensagem quando nenhuma nova CVE
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        message = f"✅ Nenhuma nova vulnerabilidade encontrada.\nAtivos monitorados: {', '.join(ASSETS)}\n🕒 {now_str}"
        await channel.send(message)


# -------------------------------
# LOOP AUTOMÁTICO
# -------------------------------
@tasks.loop(minutes=40)
async def check_nvd_task():
    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        await cleanup_messages(channel)
        vulns = fetch_nvd()
        alerts = filter_assets_last(vulns)
        await send_alerts(channel, alerts)


@bot.event
async def on_ready():
    print(f"✅ Bot conectado como {bot.user}")
    check_nvd_task.start()


# -------------------------------
# INICIA O BOT
# -------------------------------
bot.run(DISCORD_TOKEN)
