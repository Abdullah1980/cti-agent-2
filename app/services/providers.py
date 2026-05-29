import base64
import asyncio
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.core.models import Language, SourceVerdict


def _vt_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded


def _vt_endpoint(ioc_type: str, value: str) -> str | None:
    if ioc_type == "ip":
        return f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    if ioc_type == "domain":
        return f"https://www.virustotal.com/api/v3/domains/{value}"
    if ioc_type == "url":
        return f"https://www.virustotal.com/api/v3/urls/{_vt_url_id(value)}"
    if ioc_type == "hash":
        return f"https://www.virustotal.com/api/v3/files/{value}"
    return None


def _severity_score(malicious: int, suspicious: int) -> int:
    return min(100, malicious * 18 + suspicious * 8)


async def query_virustotal(ioc_type: str, value: str) -> SourceVerdict:
    settings = get_settings()
    if not settings.virustotal_api_key:
        return SourceVerdict(source="VirusTotal", status="not_configured", summary="VirusTotal API key is not configured.")
    endpoint = _vt_endpoint(ioc_type, value)
    if not endpoint:
        return SourceVerdict(source="VirusTotal", status="not_applicable", summary="This indicator type is not supported by the VirusTotal connector.")
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.get(endpoint, headers={"x-apikey": settings.virustotal_api_key})
        if response.status_code == 404:
            return SourceVerdict(source="VirusTotal", status="not_found", summary="No reputation record was found for this indicator.")
        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        score = _severity_score(malicious, suspicious)
        status = "malicious" if malicious else "suspicious" if suspicious else "clean"
        summary = f"malicious={malicious}, suspicious={suspicious}, harmless={harmless}"
        return SourceVerdict(source="VirusTotal", status=status, score=score, summary=summary, raw=data)
    except Exception as exc:
        return SourceVerdict(source="VirusTotal", status="error", summary=f"Connector error: {exc}")


async def query_malwarebazaar(ioc_type: str, value: str) -> SourceVerdict:
    settings = get_settings()
    if ioc_type != "hash":
        return SourceVerdict(source="MalwareBazaar", status="not_applicable", summary="MalwareBazaar is primarily applicable to file hashes.")
    if not settings.malwarebazaar_api_key:
        return SourceVerdict(source="MalwareBazaar", status="not_configured", summary="MalwareBazaar Auth Key is not configured.")
    try:
        headers = {"Auth-Key": settings.malwarebazaar_api_key}
        payload = {"query": "get_info", "hash": value}
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.post("https://mb-api.abuse.ch/api/v1/", data=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        if data.get("query_status") != "ok":
            return SourceVerdict(source="MalwareBazaar", status="not_found", summary=str(data.get("query_status", "not_found")), raw=data)
        sample = (data.get("data") or [{}])[0]
        tags = ", ".join(sample.get("tags") or [])
        signature = sample.get("signature") or "unknown"
        score = 75 if signature != "unknown" else 55
        summary = f"signature={signature}; tags={tags or 'none'}"
        return SourceVerdict(source="MalwareBazaar", status="malicious", score=score, summary=summary, raw=data)
    except Exception as exc:
        return SourceVerdict(source="MalwareBazaar", status="error", summary=f"Connector error: {exc}")


async def query_abuseipdb(ioc_type: str, value: str) -> SourceVerdict:
    settings = get_settings()
    if ioc_type != "ip":
        return SourceVerdict(source="AbuseIPDB", status="not_applicable", summary="AbuseIPDB is applicable to IP reputation checks.")
    if not settings.abuseipdb_api_key:
        return SourceVerdict(source="AbuseIPDB", status="not_configured", summary="AbuseIPDB API key is not configured.")
    try:
        headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": value, "maxAgeInDays": "90", "verbose": ""}
        last_error: Exception | None = None
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            for attempt in range(3):
                try:
                    response = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                    break
                except (httpx.ReadError, httpx.ConnectError, httpx.TimeoutException) as exc:
                    last_error = exc
                    if attempt == 2:
                        raise
                    await asyncio.sleep(0.6 * (attempt + 1))
            else:
                raise last_error or RuntimeError("AbuseIPDB request failed")
        if response.status_code in {401, 403}:
            return SourceVerdict(source="AbuseIPDB", status="error", summary="Authentication failed. Check ABUSEIPDB_API_KEY.")
        if response.status_code == 429:
            return SourceVerdict(source="AbuseIPDB", status="error", summary="Rate limit reached for AbuseIPDB.")
        if response.status_code == 422:
            return SourceVerdict(source="AbuseIPDB", status="not_applicable", summary="AbuseIPDB rejected this IP lookup request.")
        response.raise_for_status()
        data = response.json()
        item = data.get("data", {})
        confidence = int(item.get("abuseConfidenceScore", 0) or 0)
        reports = int(item.get("totalReports", 0) or 0)
        country = item.get("countryCode") or "unknown"
        usage = item.get("usageType") or "unknown"
        status = "malicious" if confidence >= 75 else "suspicious" if confidence >= 25 or reports else "clean"
        summary = f"abuseConfidenceScore={confidence}, totalReports={reports}, country={country}, usageType={usage}"
        return SourceVerdict(source="AbuseIPDB", status=status, score=confidence, summary=summary, raw=data)
    except httpx.HTTPStatusError as exc:
        body = exc.response.text[:240] if exc.response is not None else ""
        return SourceVerdict(source="AbuseIPDB", status="error", summary=f"HTTP {exc.response.status_code}: {body}")
    except (httpx.ReadError, httpx.ConnectError, httpx.TimeoutException) as exc:
        return SourceVerdict(source="AbuseIPDB", status="source_unavailable", summary=f"Temporary source connectivity issue after retries: {exc.__class__.__name__}")
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        return SourceVerdict(source="AbuseIPDB", status="error", summary=f"Connector error: {detail}")


def _urlscan_query(ioc_type: str, value: str) -> str | None:
    if ioc_type == "domain":
        return f'domain:"{value}"'
    if ioc_type == "ip":
        return f'ip:"{value}"'
    if ioc_type == "url":
        return f'page.url:"{value}" OR task.url:"{value}"'
    return None


async def query_urlscan(ioc_type: str, value: str) -> SourceVerdict:
    settings = get_settings()
    query = _urlscan_query(ioc_type, value)
    if not query:
        return SourceVerdict(source="URLScan", status="not_applicable", summary="URLScan search is applicable to URLs, domains, and IPs.")
    if not settings.urlscan_api_key:
        return SourceVerdict(source="URLScan", status="not_configured", summary="URLScan API key is not configured.")
    try:
        headers = {"API-Key": settings.urlscan_api_key}
        params = {"q": query, "size": "10"}
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.get("https://urlscan.io/api/v1/search/", headers=headers, params=params)
        if response.status_code == 400:
            return SourceVerdict(source="URLScan", status="not_applicable", summary="URLScan rejected this search query format.")
        response.raise_for_status()
        data = response.json()
        results = data.get("results", []) or []
        malicious = 0
        suspicious = 0
        for result in results:
            verdicts = result.get("verdicts", {}) or {}
            overall = verdicts.get("overall", {}) or {}
            if overall.get("malicious"):
                malicious += 1
            elif overall.get("score", 0):
                suspicious += 1
        score = min(100, malicious * 35 + suspicious * 12)
        status = "malicious" if malicious else "suspicious" if suspicious else "clean" if results else "not_found"
        summary = f"results={len(results)}, malicious_results={malicious}, suspicious_results={suspicious}"
        return SourceVerdict(source="URLScan", status=status, score=score, summary=summary, raw=data)
    except (httpx.ReadError, httpx.ConnectError, httpx.TimeoutException) as exc:
        return SourceVerdict(source="URLScan", status="source_unavailable", summary=f"Temporary source connectivity issue after retries: {exc.__class__.__name__}")
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        return SourceVerdict(source="URLScan", status="error", summary=f"Connector error: {detail}")


def _otx_type(ioc_type: str, value: str) -> str | None:
    if ioc_type == "ip":
        return "IPv4"
    if ioc_type == "domain":
        return "domain"
    if ioc_type == "url":
        return "url"
    if ioc_type == "hash":
        if len(value) == 32:
            return "FileHash-MD5"
        if len(value) == 40:
            return "FileHash-SHA1"
        if len(value) == 64:
            return "FileHash-SHA256"
    return None


async def query_otx(ioc_type: str, value: str) -> SourceVerdict:
    settings = get_settings()
    otx_type = _otx_type(ioc_type, value)
    if not otx_type:
        return SourceVerdict(source="OTX", status="not_applicable", summary="OTX lookup is applicable to IPs, domains, URLs, and file hashes.")
    if not settings.otx_api_key:
        return SourceVerdict(source="OTX", status="not_configured", summary="OTX API key is not configured.")
    try:
        encoded = quote(value, safe="")
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{encoded}/general"
        headers = {"X-OTX-API-KEY": settings.otx_api_key}
        last_error: Exception | None = None
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            for attempt in range(3):
                try:
                    response = await client.get(endpoint, headers=headers)
                    break
                except (httpx.ReadError, httpx.ConnectError, httpx.TimeoutException) as exc:
                    last_error = exc
                    if attempt == 2:
                        raise
                    await asyncio.sleep(0.6 * (attempt + 1))
            else:
                raise last_error or RuntimeError("OTX request failed")
        if response.status_code == 404:
            return SourceVerdict(source="OTX", status="not_found", summary="No OTX record was found for this indicator.")
        response.raise_for_status()
        data = response.json()
        pulse_info = data.get("pulse_info", {}) or {}
        pulse_count = int(pulse_info.get("count", 0) or 0)
        reputation = int(data.get("reputation", 0) or 0) if str(data.get("reputation", "0")).lstrip("-").isdigit() else 0
        validation = data.get("validation") or []
        score = min(100, pulse_count * 15 + max(reputation, 0) * 5)
        status = "malicious" if score >= 75 else "suspicious" if pulse_count or reputation > 0 or validation else "clean"
        summary = f"pulses={pulse_count}, reputation={reputation}, validation_entries={len(validation)}"
        return SourceVerdict(source="OTX", status=status, score=score, summary=summary, raw=data)
    except httpx.HTTPStatusError as exc:
        body = exc.response.text[:240] if exc.response is not None else ""
        return SourceVerdict(source="OTX", status="error", summary=f"HTTP {exc.response.status_code}: {body}")
    except (httpx.ReadError, httpx.ConnectError, httpx.TimeoutException) as exc:
        return SourceVerdict(source="OTX", status="source_unavailable", summary=f"Temporary source connectivity issue after retries: {exc.__class__.__name__}")
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        return SourceVerdict(source="OTX", status="error", summary=f"Connector error: {detail}")


async def summarize_with_openai(company_name: str, compact_findings: list[dict[str, Any]], context: str, language: Language) -> dict[str, str] | None:
    settings = get_settings()
    if not settings.openai_api_key:
        return None

    output_language = "Arabic" if language == "ar" else "English"
    prompt = {
        "company": company_name,
        "language": output_language,
        "context": context,
        "findings": compact_findings,
        "required_output": {
            "executive": f"{output_language} executive summary for senior leadership, risk, business impact, and decisions.",
            "operations": f"{output_language} SOC operations summary with containment, hunting, and monitoring actions.",
            "technical": f"{output_language} technical summary with IOC evidence, MITRE mapping, confidence, and next steps.",
        },
    }
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.post(
                "https://api.openai.com/v1/responses",
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.openai_model,
                    "input": [
                        {
                            "role": "system",
                            "content": f"You are a senior cyber threat intelligence analyst. Return concise {output_language} JSON only.",
                        },
                        {"role": "user", "content": str(prompt)},
                    ],
                    "text": {
                        "format": {
                            "type": "json_schema",
                            "name": "cti_summaries",
                            "schema": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "executive": {"type": "string"},
                                    "operations": {"type": "string"},
                                    "technical": {"type": "string"},
                                },
                                "required": ["executive", "operations", "technical"],
                            },
                        }
                    },
                },
            )
        response.raise_for_status()
        data = response.json()
        text = data.get("output_text")
        if not text:
            parts = data.get("output", [])
            text = "".join(
                item.get("text", "")
                for entry in parts
                for item in entry.get("content", [])
                if item.get("type") in {"output_text", "text"}
            )
        if not text:
            return None
        import json

        parsed = json.loads(text)
        return {
            "executive": parsed.get("executive", ""),
            "operations": parsed.get("operations", ""),
            "technical": parsed.get("technical", ""),
        }
    except Exception:
        return None
