import re
import asyncio
import json
from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from models.schemas import AnalyzeRequest, AnalyzeResponse, InputType
from services import virustotal, abuseipdb, nvd, shodan, hybrid_analysis, rule_based_summarizer as ai_summarizer

limiter = Limiter(key_func=get_remote_address)
router = APIRouter()


def detect_input_type(query: str) -> InputType:
    query = query.strip()

    if re.match(r"^CVE-\d{4}-\d+$", query, re.IGNORECASE):
        return InputType.cve

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
        return InputType.ip

    if re.match(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$", query):
            return InputType.ip

    if re.match(r"^[a-fA-F0-9]{32}$", query):
        return InputType.hash
    if re.match(r"^[a-fA-F0-9]{40}$", query):
        return InputType.hash
    if re.match(r"^[a-fA-F0-9]{64}$", query):
        return InputType.hash

    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", query):
        return InputType.domain

    raise HTTPException(status_code=400, detail="Input não reconhecido. Use um IP, hash, domínio ou CVE.")


@router.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("5/minute")
async def analyze(request: Request, body: AnalyzeRequest):
    query = body.query.strip()
    input_type = detect_input_type(query)
    raw_data = {}

    if input_type == InputType.ip:
        vt_data, abuse_data, shodan_data = await asyncio.gather(
            virustotal.lookup_ip(query),
            abuseipdb.lookup_ip(query),
            shodan.lookup_ip(query),
        )
        raw_data["virustotal"] = vt_data
        raw_data["abuseipdb"] = abuse_data
        raw_data["shodan"] = shodan_data

    elif input_type == InputType.hash:
        vt_data, ha_data = await asyncio.gather(
            virustotal.lookup_hash(query),
            hybrid_analysis.lookup_hash(query),
        )
        raw_data["virustotal"] = vt_data
        raw_data["hybrid_analysis"] = ha_data

    elif input_type == InputType.domain:
        vt_data, shodan_data = await asyncio.gather(
            virustotal.lookup_domain(query),
            shodan.lookup_domain(query),
        )
        raw_data["virustotal"] = vt_data
        raw_data["shodan"] = shodan_data

    elif input_type == InputType.cve:
        nvd_data = await nvd.lookup_cve(query)
        raw_data["nvd"] = nvd_data

    result = await ai_summarizer.summarize(
        query=query,
        input_type=input_type,
        raw_data=raw_data,
    )

    return result