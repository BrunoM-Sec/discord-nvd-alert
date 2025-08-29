import json
import os
from datetime import datetime

# ---------- Funções para manipulação do seen_db.json ----------

def load_seen_db(filepath):
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
            data = json.load(f)
            return data
    except json.JSONDecodeError:
        print(f"Erro ao ler {filepath}, arquivo corrompido. Criando novo.")
        return {}

def save_seen_db(data, filepath):
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
    Formata mensagem de CVE de forma uniforme
    """
    msg = f"**{cve['cve_id']}**\n"
    msg += f"Ativo: {cve['asset']}\n"
    msg += f"Data de Publicação: {cve['published_date']}\n"
    msg += f"{cve['description']}\n"
    msg += f"Link: {cve['url']}"
    if cve.get("critical"):
        msg = "CRITICAL ⚠️\n" + msg
    return msg
