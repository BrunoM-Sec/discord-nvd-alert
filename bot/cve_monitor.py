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
CVE_ORG_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

MAX_CVES_PER_ASSET = 2  # Pegar apenas 1 ou 2 CVEs mais recentes
YEARS_LIMIT = 3  # Ignorar CVEs com mais de 3 anos

def is_recent(published_date_str):
    published_date = datetime.datetime.strptime(published_date_str, "%Y-%m-%dT%H:%M:%S.%f")
    return (datetime.datetime.utcnow() - published_date).days <= YEARS_LIMIT * 365

async def fetch_new_cves(seen_db):
    """
    Consulta NVD para buscar CVEs recentes para os ativos específicos.
    Retorna uma lista de CVEs novas e críticas.
    """
    new_cves = []

    for asset_name, cpe in ASSETS_CPE.items():
        params = {
            "cpeName": cpe,
            "resultsPerPage": MAX_CVES_PER_ASSET,
            "startIndex": 0,
            "sortBy": "publishedDate",  # garante que pegue as mais recentes
            "orderBy": "desc"
        }

        try:
            response = requests.get(NVD_API_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"Erro ao consultar NVD para {asset_name}: {e}")
            continue

        count = 0
        for item in data.get("vulnerabilities", []):
            if count >= MAX_CVES_PER_ASSET:
                break

            cve_id = item["cve"]["id"]
            published = item["cve"]["published"]

            # Ignorar CVEs muito antigas
            if not is_recent(published):
                continue

            # Cruzamento básico com CVE.org
            try:
                cve_org_response = requests.get(CVE_ORG_URL + cve_id, timeout=5)
                if cve_id not in cve_org_response.text:
                    continue  # Ignorar se não existir no CVE.org
            except:
                continue

            # Checar se já foi reportada
            if cve_id in seen_db:
                is_new = False
            else:
                is_new = True
                seen_db[cve_id] = {"asset": asset_name, "timestamp": published}

            description = next(
                (desc["value"] for desc in item["cve"]["descriptions"] if desc["lang"] == "en"),
                item["cve"]["descriptions"][0]["value"]
            )
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            # Checar severidade (CVSSv3 e fallback CVSSv2)
            metrics = item["cve"].get("metrics", {})
            cvss3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
            critical = False
            base_score = 0
            if cvss3:
                base_score = cvss3[0]["cvssData"]["baseScore"]
            else:
                cvss2 = metrics.get("cvssMetricV2")
                if cvss2:
                    base_score = cvss2[0]["cvssData"]["baseScore"]

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

            count += 1

    # Retornar apenas CVEs novas
    return [cve for cve in new_cves if cve["is_new"]]
