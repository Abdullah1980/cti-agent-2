import ipaddress
import re
from collections import OrderedDict
from dataclasses import dataclass
from urllib.parse import urlparse

from app.core.models import IOCType

HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IP_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$")


@dataclass
class NormalizedIndicator:
    value: str
    original_values: list[str]
    occurrence_count: int
    type: IOCType
    host: str = ""
    parent: str = ""


def split_indicators(text: str) -> list[str]:
    tokens = re.split(r"[\s,;]+", text.strip())
    return [token.strip().strip("\"'<>") for token in tokens if token.strip()]


def normalize_indicator(value: str) -> str:
    clean = value.strip().strip("\"'<>")
    clean = clean.replace("hxxps://", "https://").replace("hxxp://", "http://")
    clean = clean.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    clean = clean.replace("[:]", ":")
    clean = clean.rstrip(".,;")
    return clean


def extract_host(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return parsed.hostname or ""
    return ""


def detect_ioc_type(value: str) -> IOCType:
    clean = normalize_indicator(value)
    if not clean:
        return "unknown"
    if HASH_RE.match(clean):
        return "hash"
    if EMAIL_RE.match(clean):
        return "email"
    try:
        ipaddress.ip_address(clean)
        return "ip"
    except ValueError:
        pass
    match = IP_PORT_RE.match(clean)
    if match:
        try:
            ipaddress.ip_address(match.group(1))
            return "ip"
        except ValueError:
            pass
    parsed = urlparse(clean)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"
    if DOMAIN_RE.match(clean):
        return "domain"
    return "unknown"


def value_for_lookup(value: str, ioc_type: IOCType) -> str:
    if ioc_type == "ip":
        match = IP_PORT_RE.match(value)
        if match:
            return match.group(1)
    return value


def normalize_indicators(text: str) -> list[NormalizedIndicator]:
    grouped: OrderedDict[str, NormalizedIndicator] = OrderedDict()
    for raw in split_indicators(text):
        normalized = normalize_indicator(raw)
        ioc_type = detect_ioc_type(normalized)
        lookup_value = value_for_lookup(normalized, ioc_type)
        key = lookup_value.lower() if ioc_type in {"domain", "url", "email"} else lookup_value
        host = extract_host(lookup_value) if ioc_type == "url" else ""
        parent = host if host and host != lookup_value else ""
        if key not in grouped:
            grouped[key] = NormalizedIndicator(
                value=lookup_value,
                original_values=[raw],
                occurrence_count=1,
                type=ioc_type,
                host=host,
                parent=parent,
            )
        else:
            item = grouped[key]
            item.occurrence_count += 1
            if raw not in item.original_values:
                item.original_values.append(raw)
    return list(grouped.values())
