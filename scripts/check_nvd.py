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
# FUNÇÃO: Filtra ativos e pega a última CVE
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
# FUNÇÃO: Limpa mensagens antigas (>6h)
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
# FUNÇÃO: Envia alerta no Discord (plain text)
# -------------------------------
async def send_alerts(channel, alerts):
    seen = load_seen()
    any_new = False
    msg_lines = []

    for asset, cve in alerts.items():
        if cve:
            # marca como nova se não estiver no JSON
            if cve["id"] not in seen:
                seen.append(cve["id"])
                any_new = True
            # separa por ativo no formato desejado
            msg_lines.append(
                f"┣ {asset} ┩\n"
                f"{cve['id']} / {cve['published']} UTC\n"
                f"🔗 {cve['url']}\n"
            )

    save_seen(seen)

    if any_new:
        message = "@everyone\n\n" + "\n".join(msg_lines)
        await channel.send(message)
    else:
        message = (
            "✅ Nenhuma nova vulnerabilidade encontrada.\n"
            "Ativos monitorados: " + ", ".join(ASSETS) + "\n"
            f"🕒 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
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
# INICIAR BOT
# -------------------------------
bot.run(DISCORD_TOKEN)
