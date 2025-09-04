import requests
from bs4 import BeautifulSoup
from datetime import datetime
from utils import load_seen_db, save_seen_db, is_critical
from config import ASSETS_URLS, YEARS_LIMIT

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def is_recent(published_date_str):
    try:
        published_date = datetime.strptime(published_date_str, "%Y-%m-%dT%H:%M:%S.%f")
        return (datetime.utcnow() - published_date).days <= YEARS_LIMIT * 365
    except Exception:
        return False

def fetch_latest_cves_from_cveorg(url, max_results=1):
    """
    Consulta CVE.org e retorna até max_results CVEs mais recentes.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        container = soup.find("div", {"id": "cve-search-results-container"})
        if not container:
            return []

        # Pega links dentro do container
        links = container.find_all("a", href=True)
        cves = []
        for link in links:
            href = link.get("href", "")
            if "/CVERecord/" in href:
                cve_id = link.text.strip()
                cve_url = "https://www.cve.org" + href
                cves.append({"cve_id": cve_id, "cve_url": cve_url})
                if len(cves) >= max_results:
                    break
        return cves

    except Exception as e:
        print(f"Erro ao consultar CVE.org: {e}")
        return []

def fetch_cve_details_from_nvd(cve_id):
    """
    Consulta NVD para pegar detalhes de severidade e data da CVE
    """
    try:
        response = requests.get(f"{NVD_API_URL}?cveId={cve_id}", timeout=10)
        response.raise_for_status()
        data = response.json()
        vuln = data.get("vulnerabilities", [])[0]["cve"]

        published = vuln.get("published", None)
        metrics = vuln.get("metrics", {})
        cvss3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
        cvss2 = metrics.get("cvssMetricV2")

        base_score = 0
        if cvss3:
            base_score = cvss3[0]["cvssData"]["baseScore"]
        elif cvss2:
            base_score = cvss2[0]["cvssData"]["baseScore"]

        critical = is_critical(base_score)
        return {"published_date": published, "critical": critical, "nist_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}

    except Exception as e:
        print(f"Erro ao consultar NVD para {cve_id}: {e}")
        return {"published_date": None, "critical": False, "nist_url": ""}

async def fetch_new_cves(seen_db):
    """
    Retorna lista de CVEs novas e críticas para todos os ativos monitorados.
    Atualiza o seen_db automaticamente.
    """
    new_cves = []

    for asset, url in ASSETS_URLS.items():
        latest_cves = fetch_latest_cves_from_cveorg(url, max_results=1)
        if not latest_cves:
            continue

        for latest_cve in latest_cves:
            cve_id = latest_cve["cve_id"]
            cve_url = latest_cve["cve_url"]

            if cve_id in seen_db:
                continue  # já reportada

            # Buscar detalhes no NVD
            details = fetch_cve_details_from_nvd(cve_id)
            if not details["published_date"] or not is_recent(details["published_date"]):
                continue

            # Construir CVE completo
            cve_info = {
                "cve_id": cve_id,
                "asset": asset,
                "description": f"Nova vulnerabilidade detectada em {asset}",
                "published_date": details["published_date"],
                "cve_url": cve_url,
                "nist_url": details["nist_url"],
                "critical": details["critical"],
                "is_new": True
            }

            # Atualiza o banco
            seen_db[cve_id] = {
                "asset": asset,
                "timestamp": details["published_date"],
                "cve_id": cve_id,
                "url": cve_url,
                "nist_url": details["nist_url"],
                "critical": details["critical"]
            }

            new_cves.append(cve_info)

    save_seen_db(seen_db)
    return new_cves
