import httpx
import os
import re
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _strip_html(text: str) -> str:
    return re.sub(r'<[^>]+>', '', text).strip()


async def lookup_cve(cve_id: str) -> dict:
    headers = {"apiKey": API_KEY} if API_KEY else {}
    params = {"cveId": cve_id.upper()}

    async with httpx.AsyncClient() as client:
        response = await client.get(BASE_URL, headers=headers, params=params, timeout=15.0)
        if response.status_code != 200:
            return {"error": f"NVD retornou {response.status_code}"}

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"error": "CVE não encontrado"}

        cve = vulnerabilities[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        description_en = _strip_html(next(
            (d["value"] for d in descriptions if d["lang"] == "en"), "Sem descrição"
        ))

        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_severity = None
        cvss_vector = None

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
                cvss_vector = cvss_data.get("vectorString")
                break

        references = [r["url"] for r in cve.get("references", [])[:5]]

        return {
            "cve_id": cve_id.upper(),
            "description": description_en,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "references": references,
        }