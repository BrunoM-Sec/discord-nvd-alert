import os
import json
import requests
from datetime import datetime, timezone
import discord
from discord.ext import commands, tasks

# ==========================
# CONFIGURAÇÕES GERAIS
# ==========================
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
CHANNEL_ID = int(os.getenv("DISCORD_CHANNEL_ID", "123456789"))
CHECK_EVERY_MINUTES = int(os.getenv("CHECK_EVERY_MINUTES", "40"))  # padrão 40

# Ativos monitorados (use exatamente esses nomes; você controla o layout com eles)
ASSETS = [
    "Red Hat Enterprise Linux 9",
    "Oracle Database 19c",
    "Mozilla Firefox",
    "Juniper MX Series",
    "Ubuntu 22.04 LTS",
]

# Palavras-chave por ativo (para aumentar o recall na NVD)
KEYWORDS = {
    "Red Hat Enterprise Linux 9": ["Red Hat", "RHEL 9", "Enterprise Linux 9"],
    "Oracle Database 19c": ["Oracle Database 19c", "Oracle 19c", "Oracle Database Server 19c"],
    "Mozilla Firefox": ["Mozilla Firefox", "Firefox"],
    "Juniper MX Series": ["Juniper MX", "MX Series", "Junos OS", "Junos OS Evolved"],
    "Ubuntu 22.04 LTS": ["Ubuntu 22.04", "Ubuntu Jammy", "Jammy Jellyfish"],
}

# NVD API base (v2)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Banco de “vistas” para não duplicar; guardamos até 2 últimas CVEs por ativo
DB_FILE = "seen_bd.json"

# ==========================
# DISCORD BOT
# ==========================
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)


# ==========================
# UTIL: carregar/salvar JSON
# ==========================
def _init_seen_file_if_missing():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump({}, f, indent=2)

def load_seen_map():
    _init_seen_file_if_missing()
    try:
        with open(DB_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        data = {}
    # garantimos estrutura dict[str] -> list[entries]
    if isinstance(data, list):
        # migração de formato muito antigo; converte para dict vazio
        data = {}
    for asset in ASSETS:
        data.setdefault(asset, [])
    return data

def save_seen_map(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ==========================
# BUSCA EM NVD (NIST)
# ==========================
def fetch_latest_from_nvd(asset: str, kw_list: list[str], per_page: int = 50):
    """
    Busca CVEs recentes na NVD por palavras-chave e retorna
    as melhores candidatas (lista de dicts) ordenadas por data.
    """
    params = {
        "resultsPerPage": str(per_page),
        # usamos uma consulta ampla; a filtragem fina é por keyword localmente
        "keywordSearch": " ".join(kw_list),
    }
    try:
        r = requests.get(NVD_API, params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
    except Exception as e:
        print(f"[NVD] Erro ao consultar: {e}")
        return []

    results = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        published = cve.get("published")  # ISO 8601 ex: 2025-08-28T14:23:00.000Z
        descs = cve.get("descriptions", [])
        desc_text = " ".join(d.get("value", "") for d in descs)

        # precisa casar pelo menos UMA das keywords
        if any(kw.lower() in desc_text.lower() for kw in kw_list):
            results.append({
                "id": cve_id,
                "asset": asset,
                "published": published or "",
                "desc": desc_text[:300] + ("..." if len(desc_text) > 300 else ""),
                "source": "NVD",
                "urls": {
                    "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
                    "mitre": f"https://www.cve.org/CVERecord?id={cve_id}" if cve_id else "",
                    "cvedetails": f"https://www.cvedetails.com/cve/{cve_id}/" if cve_id else "",
                },
            })

    # ordena por data de publicação desc (mais nova primeiro)
    def _dt_key(x):
        try:
            # normaliza e converte
            return datetime.fromisoformat(x["published"].replace("Z", "+00:00"))
        except Exception:
            return datetime(1970, 1, 1, tzinfo=timezone.utc)

    results.sort(key=_dt_key, reverse=True)
    return results


# ==========================
# LAYOUT / FORMATAÇÃO
# ==========================
def fmt_utc_ymd_hm(iso_ts: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d / %H:%M UTC")
    except Exception:
        return iso_ts or "N/A"

def build_discord_message(latest_by_asset: dict[str, dict], announce_new: bool) -> str:
    """
    Monta o texto final (plain text) com o layout exato solicitado.
    Sempre lista todos os ativos.
    Se announce_new=True, inclui @everyone no topo.
    """
    lines = []
    if announce_new:
        lines.append("🚨 @everyone **Novas vulnerabilidades publicadas** 🚨\n")
    else:
        lines.append("📋 **Status das últimas vulnerabilidades conhecidas**\n")

    for asset in ASSETS:
        cve = latest_by_asset.get(asset)
        lines.append(f"┏ {asset} ┓")
        if cve:
            when = fmt_utc_ymd_hm(cve.get("published", ""))
            cve_id = cve.get("id", "N/A")
            url = cve.get("urls", {}).get("nvd") or ""
            lines.append(f"{cve_id} / {when}")
            lines.append(f"🔗 {url}")
        else:
            lines.append("Sem CVE recente encontrada.")
        lines.append("")  # linha em branco entre ativos
    return "\n".join(lines).strip()


# ==========================
# LIMPEZA DE MENSAGENS
# ==========================
async def cleanup_messages(channel: discord.TextChannel):
    """
    Apaga mensagens do bot com mais de 6 horas, exceto alertas (@everyone).
    """
    now = datetime.now(timezone.utc)
    async for msg in channel.history(limit=80):
        # não apaga alertas novos
        if "@everyone" in msg.content:
            continue
        age = (now - msg.created_at).total_seconds()
        if age > 6 * 3600:
            try:
                await msg.delete()
            except Exception:
                pass


# ==========================
# ENVIO PARA DISCORD
# ==========================
async def send_update(channel: discord.TextChannel, latest_by_asset: dict[str, dict], seen_map: dict):
    """
    Envia mensagem no Discord com layout por ativo.
    Salva no JSON até 2 últimas CVEs por ativo.
    Dispara @everyone se existir CVE nova (não presente no JSON).
    """
    any_new = False

    # Detecta novidade e atualiza JSON (até 2 por ativo)
    for asset in ASSETS:
        latest = latest_by_asset.get(asset)
        if not latest:
            continue
        already = [entry["id"] for entry in seen_map.get(asset, [])]
        if latest["id"] and latest["id"] not in already:
            any_new = True
            new_list = [latest] + [e for e in seen_map.get(asset, []) if e["id"] != latest["id"]]
            seen_map[asset] = new_list[:2]

    # Monta mensagem
    msg = build_discord_message(latest_by_asset, announce_new=any_new)

    # Envia
    await channel.send(msg)

    # Salva JSON
    save_seen_map(seen_map)


# ==========================
# LOOP PRINCIPAL
# ==========================
def collect_latest_for_all_assets():
    """
    Para cada ativo, consulta a NVD com palavras-chave e pega a CVE mais recente.
    Retorna dict[asset] = último dict de CVE (ou None).
    """
    latest_by_asset = {}
    for asset in ASSETS:
        candidates = fetch_latest_from_nvd(asset, KEYWORDS.get(asset, [asset]), per_page=70)
        latest_by_asset[asset] = candidates[0] if candidates else None
    return latest_by_asset


@tasks.loop(minutes=CHECK_EVERY_MINUTES)
async def monitor_task():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        print("Canal não encontrado. Verifique DISCORD_CHANNEL_ID.")
        return

    await cleanup_messages(channel)

    seen_map = load_seen_map()
    latest_by_asset = collect_latest_for_all_assets()
    await send_update(channel, latest_by_asset, seen_map)


@bot.event
async def on_ready():
    print(f"✅ Bot conectado como {bot.user}")
    # inicia imediatamente uma checagem ao subir
    await monitor_task()
    monitor_task.start()


# ==========================
# START
# ==========================
if __name__ == "__main__":
    bot.run(DISCORD_TOKEN)
