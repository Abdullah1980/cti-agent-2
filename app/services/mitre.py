from app.core.models import IndicatorResult, MitreTechnique


MAPPING_RULES = [
    {
        "keywords": {"phishing", "credential", "email", "url", "domain"},
        "technique": MitreTechnique(
            tactic="Initial Access",
            technique_id="T1566",
            technique="Phishing",
            confidence="Medium",
            rationale="Indicator reputation or type suggests possible phishing or initial access use.",
        ),
    },
    {
        "keywords": {"malware", "trojan", "ransomware", "payload", "hash", "malwarebazaar"},
        "technique": MitreTechnique(
            tactic="Execution",
            technique_id="T1204",
            technique="User Execution",
            confidence="Medium",
            rationale="A suspicious or known malicious file may require user or process execution.",
        ),
    },
    {
        "keywords": {"c2", "command", "control", "beacon", "ip", "domain"},
        "technique": MitreTechnique(
            tactic="Command and Control",
            technique_id="T1071",
            technique="Application Layer Protocol",
            confidence="Medium",
            rationale="Network indicators can represent external communication or command-and-control infrastructure.",
        ),
    },
    {
        "keywords": {"download", "dropper", "stage", "url"},
        "technique": MitreTechnique(
            tactic="Command and Control",
            technique_id="T1105",
            technique="Ingress Tool Transfer",
            confidence="Low",
            rationale="Suspicious URLs may be used to retrieve payloads or later-stage tooling.",
        ),
    },
    {
        "keywords": {"persistence", "startup", "registry"},
        "technique": MitreTechnique(
            tactic="Persistence",
            technique_id="T1547",
            technique="Boot or Logon Autostart Execution",
            confidence="Low",
            rationale="Sample context may suggest persistence behavior requiring host validation.",
        ),
    },
]

DEFAULT_BY_TYPE = {
    "ip": MitreTechnique(
        tactic="Command and Control",
        technique_id="T1071",
        technique="Application Layer Protocol",
        confidence="Low",
        rationale="Suspicious IPs often require validation as possible communication infrastructure.",
    ),
    "domain": MitreTechnique(
        tactic="Command and Control",
        technique_id="T1071",
        technique="Application Layer Protocol",
        confidence="Low",
        rationale="Suspicious domains may support external communication or delivery infrastructure.",
    ),
    "url": MitreTechnique(
        tactic="Initial Access",
        technique_id="T1566.002",
        technique="Phishing: Spearphishing Link",
        confidence="Low",
        rationale="Suspicious URLs can be used as phishing links or payload delivery locations.",
    ),
    "hash": MitreTechnique(
        tactic="Execution",
        technique_id="T1204.002",
        technique="User Execution: Malicious File",
        confidence="Low",
        rationale="File hashes require validation for execution, prevalence, and host impact.",
    ),
    "email": MitreTechnique(
        tactic="Initial Access",
        technique_id="T1566",
        technique="Phishing",
        confidence="Low",
        rationale="Email indicators may relate to phishing senders, targets, or infrastructure.",
    ),
}


def map_to_mitre(indicator_type: str, evidence_text: str) -> list[MitreTechnique]:
    lowered = evidence_text.lower()
    matches: list[MitreTechnique] = []
    seen: set[str] = set()
    for rule in MAPPING_RULES:
        if any(keyword in lowered for keyword in rule["keywords"]):
            technique = rule["technique"]
            if technique.technique_id not in seen:
                matches.append(technique)
                seen.add(technique.technique_id)
    fallback = DEFAULT_BY_TYPE.get(indicator_type)
    if fallback and fallback.technique_id not in seen:
        matches.append(fallback)
    return matches[:4]


def aggregate_mitre(results: list[IndicatorResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        for item in result.mitre:
            key = f"{item.technique_id} - {item.technique}"
            counts[key] = counts.get(key, 0) + 1
    return counts
