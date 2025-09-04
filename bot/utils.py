import json
import os
from datetime import datetime
from config import SEEN_DB_PATH

# ---------- Funções de manipulação do seen_db ----------

def load_seen_db(filepath=SEEN_DB_PATH):
    """
    Carrega o banco de CVEs já reportadas.
    Se não existir, cria um dicionário vazio.
    """
    if not os.path.exists(filepath):
        with open(filepath, "w") as f:
            json.dump({}, f)
        return {}

    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Aviso: {filepath} corrompido. Criando novo banco vazio.")
        return {}

def save_seen_db(data, filepath=SEEN_DB_PATH):
    """
    Salva o banco de CVEs já reportadas.
    """
    try:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Erro ao salvar {filepath}: {e}")

# ---------- Funções utilitárias ----------

def current_utc_time():
    """Retorna a hora atual em UTC"""
    return datetime.utcnow()

def is_critical(cvss_score, threshold=9.0):
    """Determina se uma CVE é crítica com base no CVSS"""
    try:
        return float(cvss_score) >= threshold
    except (ValueError, TypeError):
        return False

def format_cve_message(cve):
    """
    Formata a mensagem de CVE de forma uniforme para envio no Discord
    """
    msg = f"**{cve['cve_id']}**\n"
    msg += f"Ativo: {cve['asset']}\n"
    msg += f"Data de Publicação: {cve['published_date']}\n"
    msg += f"{cve['description']}\n"
    msg += f"Links: CVE.org({cve.get('cve_url','')}) | NVD({cve.get('nist_url','')})"
    return msg
