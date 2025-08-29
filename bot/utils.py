import json
import os
import tempfile
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
        print(f"[WARNING] Erro ao ler {filepath}, arquivo corrompido. Criando novo.")
        return {}
    except Exception as e:
        print(f"[ERROR] Falha ao ler {filepath}: {e}")
        return {}

def save_seen_db(data, filepath):
    """
    Salva o banco de CVEs já reportadas de forma segura (atomic write).
    """
    try:
        dir_name = os.path.dirname(filepath)
        with tempfile.NamedTemporaryFile("w", delete=False, dir=dir_name) as tmp_file:
            json.dump(data, tmp_file, indent=4)
            temp_name = tmp_file.name
        os.replace(temp_name, filepath)  # substitui arquivo antigo de forma segura
    except Exception as e:
        print(f"[ERROR] Falha ao salvar {filepath}: {e}")

# ---------- Funções utilitárias ----------

def current_utc_time():
    """Retorna a hora atual em UTC"""
    return datetime.utcnow()

def is_critical(cvss_score, threshold=9.0):
    """
    Determina se uma CVE é crítica com base no CVSS score.
    cvss_score: número (float) ou string convertível em float.
    """
    try:
        return float(cvss_score) >= threshold
    except (ValueError, TypeError):
        return False

def format_cve_message(cve):
    """
    Formata mensagem de CVE de forma uniforme para envio no Discord.
    """
    msg = f"**{cve.get('cve_id', 'N/A')}**\n"
    msg += f"Ativo: {cve.get('asset', 'Desconhecido')}\n"
    msg += f"Data de Publicação: {cve.get('published_date', 'Desconhecida')}\n"
    msg += f"{cve.get('description', 'Sem descrição')}\n"
    msg += f"Link: {cve.get('url', 'N/A')}"
    if cve.get('critical'):
        msg = "[CRITICAL] " + msg
    return msg
