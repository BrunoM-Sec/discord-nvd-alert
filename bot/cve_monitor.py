import requests
import datetime
from utils import load_seen_db

# Constantes dos ativos monitorados (CPEs aproximados)
ASSETS_CPE = {
    "Red Hat Enterprise Linux 9": "cpe:2.3:o:redhat:enterprise_linux:9",
    "Oracle Database 19c": "cpe:2.3:a:oracle:database:19c",
    "Mozilla Firefox": "cpe:2.3:a:mozilla:firefox",
    "Juniper MX Series": "cpe:2.3:h:juniper:mx_series",
    "Ubuntu 22.04": "cpe:2.3:o:canonical:ubuntu_linux:22.04"
}

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def fetch_new_cves(seen_db):
    """
    Consulta NVD para buscar CVEs recentes para os ativos específicos.
    Retorna uma lista de CVEs novas e críticas.
    """
    new_cves = []

    for asset_name, cpe in ASSETS_CPE.items():
        params = {
            "cpeName": cpe,
            "resultsPerPage": 20,  # pegar as 20 mais recentes
            "startIndex": 0,
            # "cvssV3Severity": "HIGH"  # opcional: filtrar severidade
        }

        try:
            response = requests.get(NVD_API_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"Erro ao consultar NVD para {asset_name}: {e}")
            continue

        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            description = item["cve"]["descriptions"][0]["value"]
            published = item["cve"]["published"]
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            # Checar se já foi reportada
            if cve_id in seen_db:
                is_new = False
            else:
                is_new = True
                seen_db[cve_id] = {"asset": asset_name, "timestamp": published}

            # Checar severidade (CVSSv3)
            metrics = item["cve"].get("metrics", {})
            cvss3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
            critical = False
            if cvss3:
                base_score = cvss3[0]["cvssData"]["baseScore"]
                if base_score >= 9.0:
                    critical = True

            new_cves.append({
                "cve_id": cve_id,
                "description": description,
                "published_date": published,
                "url": url,
                "critical": critical,
                "is_new": is_new,
                "asset": asset_name
            })

    # Retornar apenas CVEs novas
    return [cve for cve in new_cves if cve["is_new"]]


