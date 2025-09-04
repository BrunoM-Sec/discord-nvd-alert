# config.py

# Caminho do banco de CVEs já reportadas
SEEN_DB_PATH = "data/seen_db.json"

# URLs de busca por ativo (CVE.org) - precisão máxima
ASSETS_URLS = {
    "Red Hat Enterprise Linux 9": "https://www.cve.org/CVERecord/SearchResults?query=red+hat+enterprise+linux+9",
    "Oracle Database 19c": "https://www.cve.org/CVERecord/SearchResults?query=oracle+database+19c",
    "Mozilla Firefox": "https://www.cve.org/CVERecord/SearchResults?query=mozilla+firefox",
    "Juniper MX Series": "https://www.cve.org/CVERecord/SearchResults?query=Juniper+Mx+Series",
    "Ubuntu 22.04": "https://www.cve.org/CVERecord/SearchResults?query=ubuntu+22.04"
}

# Limites de consulta
MAX_CVES_PER_ASSET = 2   # Número máximo de CVEs recentes por ativo
YEARS_LIMIT = 3          # Ignorar CVEs com mais de 3 anos

# Auto-clean do Discord
AUTO_CLEAN_INTERVAL_MINUTES = 6*60 + 20  # 6h20min
PRESERVE_MINUTES = 20                     # Mensagens recentes a preservar

