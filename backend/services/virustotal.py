import httpx
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY}


async def lookup_ip(ip: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/ip_addresses/{ip}", headers=HEADERS)
        if response.status_code != 200:
            return {"error": f"VirusTotal retornou {response.status_code}"}
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless": attrs.get("last_analysis_stats", {}).get("harmless", 0),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "reputation": attrs.get("reputation"),
        }


async def lookup_hash(file_hash: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/files/{file_hash}", headers=HEADERS)
        if response.status_code != 200:
            return {"error": f"VirusTotal retornou {response.status_code}"}
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless": attrs.get("last_analysis_stats", {}).get("harmless", 0),
            "name": attrs.get("meaningful_name"),
            "type": attrs.get("type_description"),
            "size": attrs.get("size"),
            "tags": attrs.get("tags", []),
        }


async def lookup_domain(domain: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/domains/{domain}", headers=HEADERS)
        if response.status_code != 200:
            return {"error": f"VirusTotal retornou {response.status_code}"}
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless": attrs.get("last_analysis_stats", {}).get("harmless", 0),
            "reputation": attrs.get("reputation"),
            "registrar": attrs.get("registrar"),
            "categories": attrs.get("categories", {}),
        }