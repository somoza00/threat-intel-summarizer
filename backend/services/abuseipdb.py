import httpx
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2"


async def lookup_ip(ip: str) -> dict:
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/check", headers=headers, params=params)
        if response.status_code != 200:
            return {"error": f"AbuseIPDB retornou {response.status_code}"}
        data = response.json().get("data", {})
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "is_public": data.get("isPublic"),
            "usage_type": data.get("usageType"),
            "last_reported_at": data.get("lastReportedAt"),
        }