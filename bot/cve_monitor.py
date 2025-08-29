import requests
import datetime
from dateutil import parser
from utils import load_seen_db

# Constantes dos ativos monitorados (CPEs estritos)
ASSETS_CPE = {
    "Red Hat Enterprise Linux 9": "cpe:2.3:o:redhat:enterprise_linux:9",
    "Oracle Database 19c": "cpe:2.3:a:oracle:database:19c",
    "Mozilla Firefox": "cpe:2.3:a:mozilla:firefox",
    "Juniper MX Series": "cpe:2.3:h:juniper:mx_series",
    "Ubuntu 22.04": "cpe:2.3:o:canonical:ubuntu_linux:22.04"
}

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

YEARS_LIMIT = 3  # Ignorar CVEs com mais de 3 anos
MAX_CVES_PER_ASSET = 2  # Apenas as últimas 1-2 CVEs por ativo

def is_recent(published_date_str):
    try:
        published_date = parser.parse(published_date_str)
    except Exception:
        return False
    return (datetime.datetime.utcnow() - published_date).days <= YEARS_LIMIT * 365

async def fetch_new_cves(seen_db):
    new_cves = []

    for asset_name, cpe in ASSETS_CPE.items():
        params = {
            "cpeName": cpe,
            "resultsPerPage": 100,  # pegar todas recentes do último ano
            "startIndex": 0,
            "sortBy": "publishedDate",
            "orderBy": "desc"
        }

        try:
            response = requests.get(NVD_API_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"Erro ao consultar NVD para {asset_name}: {e}")
            continue

        # Filtrar somente CVEs recentes (<3 anos) e correspondentes ao CPE exato
        recent_cves = []
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            published = item["cve"]["published"]

            # Ignorar CVEs muito antigas
            if not is_recent(published):
                continue

            # Verificar se o CPE corresponde exatamente
            cpe_matches = [v["cpe23Uri"] for v in item["cve"].get("configurations", {}).get("nodes", []) if "cpeMatch" in v]
            exact_match = any(cpe == cm for node in item["cve"].get("configurations", {}).get("nodes", []) 
                              for cm in node.get("cpeMatch", []) if "cpe23Uri" in cm)
            if not exact_match:
                continue

            # Cruzamento básico com CVE.org
            try:
                cve_org_response = requests.get(CVE_ORG_URL + cve_id, timeout=5)
                if cve_id not in cve_org_response.text:
                    continue
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
                else:
                    # fallback severidade textual
                    sev_text = item["cve"].get("problemtype", {}).get("problemtype_data", [])
                    if sev_text:
                        critical = any("Critical" in pt["description"][0]["value"] for pt in sev_text)

            if base_score >= 9.0:
                critical = True

            recent_cves.append({
                "cve_id": cve_id,
                "description": description,
                "published_date": published,
                "url": url,
                "critical": critical,
                "is_new": is_new,
                "asset": asset_name
            })

        # Ordenar por data e pegar somente as MAX_CVES_PER_ASSET mais recentes
        recent_cves.sort(key=lambda x: x["published_date"], reverse=True)
        new_cves.extend(recent_cves[:MAX_CVES_PER_ASSET])

    return [cve for cve in new_cves if cve["is_new"]]
