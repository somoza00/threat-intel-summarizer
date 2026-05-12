import httpx
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("SHODAN_API_KEY")
BASE_URL = "https://api.shodan.io"


async def lookup_ip(ip: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{BASE_URL}/shodan/host/{ip}",
            params={"key": API_KEY},
        )
        if response.status_code == 404:
            return {"error": "IP não encontrado no Shodan"}
        if response.status_code != 200:
            return {"error": f"Shodan retornou {response.status_code}"}
        data = response.json()

        services = []
        for item in data.get("data", [])[:10]:
            svc = {"port": item.get("port"), "transport": item.get("transport")}
            if item.get("product"):
                svc["product"] = item["product"]
            if item.get("version"):
                svc["version"] = item["version"]
            services.append(svc)

        return {
            "ports": data.get("ports", []),
            "services": services,
            "vulns": list(data.get("vulns", {}).keys()),
            "org": data.get("org"),
            "os": data.get("os"),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update"),
        }


async def lookup_domain(domain: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{BASE_URL}/dns/domain/{domain}",
            params={"key": API_KEY},
        )
        if response.status_code == 404:
            return {"error": "Domínio não encontrado no Shodan"}
        if response.status_code != 200:
            return {"error": f"Shodan retornou {response.status_code}"}
        data = response.json()

        dns_records = data.get("data", [])
        ips = list({
            r.get("value") for r in dns_records
            if r.get("type") in ("A", "AAAA") and r.get("value")
        })

        return {
            "domain": data.get("domain"),
            "subdomains": data.get("subdomains", [])[:10],
            "ips": ips[:5],
            "tags": data.get("tags", []),
        }
