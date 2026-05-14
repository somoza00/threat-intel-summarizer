import httpx
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews", "source": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/", "source": "Bleeping Computer"},
    {"url": "https://www.cisa.gov/news.xml", "source": "CISA"},
]

_cache: dict = {"items": [], "fetched_at": None}
CACHE_TTL_SECONDS = 3600


def _parse_date(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return raw[:25] if raw else None


def _parse_feed(xml_text: str, source: str) -> list[dict]:
    items = []
    try:
        root = ET.fromstring(xml_text)
        ns = {}
        channel = root.find("channel")
        if channel is None:
            return items
        for item in channel.findall("item")[:6]:
            title_el = item.find("title")
            link_el = item.find("link")
            pub_el = item.find("pubDate")
            desc_el = item.find("description")

            title = title_el.text.strip() if title_el is not None and title_el.text else ""
            link = link_el.text.strip() if link_el is not None and link_el.text else ""
            pub = _parse_date(pub_el.text if pub_el is not None else None)
            desc = desc_el.text or "" if desc_el is not None else ""
            # Strip HTML tags from description
            import re
            desc = re.sub(r"<[^>]+>", "", desc).strip()
            desc = desc[:180] + "..." if len(desc) > 180 else desc

            if title and link:
                items.append({
                    "title": title,
                    "link": link,
                    "published_at": pub,
                    "description": desc,
                    "source": source,
                })
    except ET.ParseError:
        pass
    return items


async def fetch_news() -> list[dict]:
    now = datetime.now(timezone.utc).timestamp()
    if _cache["fetched_at"] and (now - _cache["fetched_at"]) < CACHE_TTL_SECONDS:
        return _cache["items"]

    all_items: list[dict] = []
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        for feed in FEEDS:
            try:
                response = await client.get(feed["url"])
                if response.status_code == 200:
                    all_items.extend(_parse_feed(response.text, feed["source"]))
            except Exception:
                continue

    all_items.sort(key=lambda x: x.get("published_at") or "", reverse=True)

    _cache["items"] = all_items[:18]
    _cache["fetched_at"] = now
    return _cache["items"]
