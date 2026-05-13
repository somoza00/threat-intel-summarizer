import httpx
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
BASE_URL = "https://www.hybrid-analysis.com/api/v2"

HEADERS = {
    "api-key": API_KEY or "",
    "user-agent": "Falcon Sandbox",
    "accept": "application/json",
}


async def lookup_hash(file_hash: str) -> dict:
    if not API_KEY:
        return {"error": "HYBRID_ANALYSIS_API_KEY não configurada"}

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            f"{BASE_URL}/search/hash",
            headers=HEADERS,
            data={"hash": file_hash},
        )
        if response.status_code == 404:
            return {"error": "Hash não encontrado no Hybrid Analysis"}
        if response.status_code == 401:
            return {"error": "API key inválida para o Hybrid Analysis"}
        if response.status_code != 200:
            return {"error": f"Hybrid Analysis retornou {response.status_code}"}

        results = response.json()
        if not results:
            return {"error": "Hash não encontrado no Hybrid Analysis"}

        # Pega o resultado mais recente com maior threat_score
        best = max(results, key=lambda r: r.get("threat_score") or 0)

        domains = []
        hosts = []
        for r in results:
            domains.extend(r.get("domains", []))
            hosts.extend(r.get("hosts", []))

        tags = []
        for r in results:
            tags.extend(r.get("tags") or [])

        return {
            "verdict": best.get("verdict"),
            "threat_score": best.get("threat_score"),
            "threat_level": best.get("threat_level"),
            "av_detect": best.get("av_detect"),
            "type_short": best.get("type_short"),
            "submit_name": best.get("submit_name"),
            "environment": best.get("environment_description"),
            "analysis_time": (best.get("analysis_start_time") or "")[:10] or None,
            "domains": list(set(domains))[:10],
            "hosts": list(set(hosts))[:10],
            "tags": list(set(tags))[:10],
            "total_reports": len(results),
        }
