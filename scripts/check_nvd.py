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
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"

# -------------------------------
# BOT DISCORD
# -------------------------------
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

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
    matched = {asset: [] for asset in ASSETS}
    for v in vulns:
        cve = v.get("cve", {})
        descs = cve.get("descriptions", [])
        desc_text = " ".join(d.get("value","") for d in descs)
        published = cve.get("published", "")  # pega data de publicação
        cve_id = cve.get("id", "")
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        for asset in ASSETS:
            if asset.lower() in desc_text.lower():
                matched[asset].append({
                    "id": cve_id,
                    "desc": desc_text[:200] + "...",
                    "url": url,
                    "published": published
                })
    return matched

# -------------------------------
# FUNÇÃO: Apaga mensagens antigas (>6h)
# -------------------------------
async def cleanup_messages(channel):
    now = datetime.now(timezone.utc)
    async for msg in channel.history(limit=50):
        if (now - msg.created_at).total_seconds() > 21600:
            try:
                await msg.delete()
            except:
                pass

# -------------------------------
# FUNÇÃO: Envia alerta
# -------------------------------
async def send_alerts(channel, alerts_dict):
    seen = load_seen()
    new_alerts_found = False
    msg_parts = []

    for asset, alerts in alerts_dict.items():
        if not alerts:
            msg_parts.append(f"|-- {asset} --|\nNenhuma nova CVE\n")
            continue

        # Pega apenas a última CVE publicada
        alerts_sorted = sorted(alerts, key=lambda x: x.get("published", ""), reverse=True)
        last_alert = alerts_sorted[0]

        if last_alert["id"] not in seen:
            new_alerts_found = True
            seen.append(last_alert["id"])

        msg_parts.append(
            f"|-- {asset} --|\n"
            f"{last_alert['id']} / {last_alert['published']}\n"
            f"🔗 {last_alert['url']}\n"
        )

    save_seen(seen)

    final_msg = "\n".join(msg_parts)
    if new_alerts_found:
        final_msg = f"🚨 @everyone **Novas Vulnerabilidades Encontradas!** 🚨\n\n" + final_msg

    await channel.send(final_msg)

# -------------------------------
# LOOP AUTOMÁTICO
# -------------------------------
@tasks.loop(minutes=40)
async def check_nvd_task():
    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        await cleanup_messages(channel)
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
