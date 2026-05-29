import asyncio
import json
from datetime import datetime
from uuid import uuid4

from app.core.config import ANALYSES_DIR
from app.core.models import AnalysisResult, IndicatorResult, Language, ReportSummaries, SourceVerdict
from app.services.ioc import normalize_indicators
from app.services.mitre import aggregate_mitre, map_to_mitre
from app.services.providers import (
    query_abuseipdb,
    query_malwarebazaar,
    query_otx,
    query_urlscan,
    query_virustotal,
    summarize_with_openai,
)
from app.services.storage import auto_case_for_analysis


LABEL_KEYWORDS = {
    "phishing": {"phishing", "spearphishing", "credential", "login"},
    "malware": {"malware", "trojan", "ransomware", "signature", "payload"},
    "c2": {"c2", "command", "control", "beacon"},
    "payload-delivery": {"download", "dropper", "bin.sh", "wget", "apk", "payload"},
    "abuse-reported": {"abuseconfidencescore", "totalreports"},
    "known-threat-intel": {"pulse", "pulses", "reputation", "validation"},
}

BENIGN_HINTS = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "example.com",
    "google.com",
    "microsoft.com",
    "openai.com",
}


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def source_agreement(verdicts: list[SourceVerdict]) -> dict[str, int]:
    counts = {
        "malicious": 0,
        "suspicious": 0,
        "clean": 0,
        "not_found": 0,
        "not_applicable": 0,
        "source_unavailable": 0,
        "error": 0,
        "not_configured": 0,
    }
    for verdict in verdicts:
        counts[verdict.status] = counts.get(verdict.status, 0) + 1
    counts["active_sources"] = sum(
        1 for verdict in verdicts if verdict.status not in {"not_applicable", "not_configured", "error", "source_unavailable"}
    )
    return counts


def confidence_from_agreement(agreement: dict[str, int], risk_score: int) -> str:
    harmful = agreement.get("malicious", 0) + agreement.get("suspicious", 0)
    active_sources = agreement.get("active_sources", 0)
    if harmful >= 2 or (harmful >= 1 and active_sources >= 3 and risk_score >= 75):
        return "High"
    if harmful == 1 or active_sources >= 2 or risk_score >= 40:
        return "Medium"
    return "Low"


def threat_labels(indicator: str, indicator_type: str, verdicts: list[SourceVerdict], mitre_text: str) -> list[str]:
    source_text = " ".join([indicator, indicator_type, *[v.status + " " + v.summary for v in verdicts]]).lower()
    mitre_lower = mitre_text.lower()
    labels: list[str] = []
    for label, keywords in LABEL_KEYWORDS.items():
        if any(keyword in source_text for keyword in keywords):
            labels.append(label)
    if not labels and "phishing" in mitre_lower and indicator_type in {"url", "domain", "email"}:
        labels.append("possible-phishing")
    if not labels and "command and control" in mitre_lower and indicator_type in {"ip", "domain"}:
        labels.append("possible-c2")
    if indicator.lower() in BENIGN_HINTS:
        labels.append("public-infrastructure")
    if indicator_type == "hash":
        labels.append("file-hash")
    if indicator_type == "url" and "payload-delivery" not in labels:
        labels.append("url-observed")
    return sorted(set(labels))


def recommended_actions(indicator_type: str, severity: str, language: Language, labels: list[str] | None = None) -> list[str]:
    labels = labels or []
    if language == "en":
        actions = [
            "Search SIEM and EDR telemetry for the indicator over the last 30 days.",
            "Add the indicator to a temporary watchlist until validation is complete.",
        ]
        if severity in {"High", "Critical"}:
            actions.insert(0, "Block the indicator on appropriate controls after confirming business impact.")
            actions.append("Open an incident review ticket and link any affected assets.")
        if indicator_type in {"url", "domain"}:
            actions.append("Review DNS, proxy, and web gateway logs for users or hosts that attempted access.")
        if indicator_type == "hash":
            actions.append("Hunt for the hash in EDR and isolate hosts that executed the file if needed.")
        if indicator_type == "ip":
            actions.append("Review firewall and NetFlow records for inbound and outbound communication.")
        if "public-infrastructure" in labels:
            actions.insert(0, "Validate carefully before blocking because this indicator may represent public infrastructure.")
        return actions

    actions = [
        "التحقق من ظهور المؤشر في سجلات SIEM و EDR خلال آخر 30 يومًا.",
        "إضافة المؤشر إلى قائمة مراقبة مؤقتة حتى اكتمال التحقق.",
    ]
    if severity in {"High", "Critical"}:
        actions.insert(0, "حظر المؤشر على الضوابط المناسبة بعد التأكد من عدم وجود أثر تشغيلي.")
        actions.append("فتح تذكرة مراجعة حادث وربطها بالأصول المتأثرة.")
    if indicator_type in {"url", "domain"}:
        actions.append("مراجعة سجلات DNS و Proxy و Web Gateway لتحديد المستخدمين أو الأجهزة التي حاولت الوصول.")
    if indicator_type == "hash":
        actions.append("البحث عن hash في EDR وعزل الأجهزة التي شغلت الملف عند الحاجة.")
    if indicator_type == "ip":
        actions.append("مراجعة سجلات Firewall و NetFlow للاتصالات الصادرة والواردة.")
    if "public-infrastructure" in labels:
        actions.insert(0, "تحقق بعناية قبل الحظر لأن المؤشر قد يمثل بنية عامة واسعة الاستخدام.")
    return actions


def local_summaries(company_name: str, results: list[IndicatorResult], language: Language, raw_count: int) -> ReportSummaries:
    total = len(results)
    high = sum(1 for item in results if item.severity in {"High", "Critical"})
    high_conf = sum(1 for item in results if item.confidence == "High")
    top = sorted(results, key=lambda item: item.risk_score, reverse=True)[:3]
    top_text = ", ".join(f"{item.value} ({item.severity}/{item.confidence})" for item in top) or "none"

    if language == "en":
        return ReportSummaries(
            executive=(
                f"{raw_count} submitted values were normalized into {total} unique indicators for {company_name}. "
                f"{high} indicators are High or Critical, with {high_conf} High-confidence assessments. "
                f"Top indicators: {top_text}. Leadership should prioritize confirmed high-risk indicators and track business exposure."
            ),
            operations=(
                "SOC operations should prioritize indicators where multiple sources agree, then run retrospective hunts across SIEM, EDR, "
                "DNS, proxy, and firewall telemetry. Use the confidence and threat labels to separate immediate containment from validation work."
            ),
            technical=(
                "The analysis includes IOC normalization, source agreement, confidence scoring, threat labels, and MITRE ATT&CK mapping. "
                "Validate raw source evidence, review not_found/not_applicable context, and enrich confirmed IOCs in TIP or SOAR."
            ),
        )

    top_text_ar = "، ".join(f"{item.value} ({item.severity}/{item.confidence})" for item in top) or "لا يوجد"
    return ReportSummaries(
        executive=(
            f"تم توحيد {raw_count} قيمة مدخلة إلى {total} مؤشر فريد لصالح {company_name}. "
            f"عدد المؤشرات عالية الخطورة أو الحرجة: {high}، وعدد التقييمات عالية الثقة: {high_conf}. "
            f"أبرز المؤشرات: {top_text_ar}. التوصية هي إعطاء الأولوية للمؤشرات عالية الخطورة والمؤكدة ومتابعة أثرها على الأعمال."
        ),
        operations=(
            "ينبغي لفريق العمليات إعطاء الأولوية للمؤشرات التي اتفقت عليها عدة مصادر، ثم تنفيذ بحث رجعي في SIEM و EDR و DNS و Proxy و Firewall. "
            "استخدم مستوى الثقة ووسوم التهديد للتمييز بين الاحتواء الفوري والتحقق الإضافي."
        ),
        technical=(
            "يشمل التحليل توحيد المؤشرات، اتفاق المصادر، مستوى الثقة، وسوم التهديد، وربط MITRE ATT&CK. "
            "ينصح بمراجعة الأدلة الخام وفهم حالات not_found و not_applicable قبل اعتماد المؤشرات المؤكدة في TIP أو SOAR."
        ),
    )


async def analyze_indicators(indicators: str, company_name: str, context: str, use_openai: bool, language: Language = "ar") -> AnalysisResult:
    normalized = normalize_indicators(indicators)
    raw_count = sum(item.occurrence_count for item in normalized)
    results: list[IndicatorResult] = []

    async def analyze_one(item) -> IndicatorResult:
        indicator_type = item.type
        value = item.value
        verdicts = await asyncio.gather(
            query_virustotal(indicator_type, value),
            query_malwarebazaar(indicator_type, value),
            query_abuseipdb(indicator_type, value),
            query_urlscan(indicator_type, value),
            query_otx(indicator_type, value),
        )
        agreement = source_agreement(list(verdicts))
        risk_score = min(100, max(verdict.score for verdict in verdicts) if verdicts else 0)
        if indicator_type == "unknown":
            risk_score = max(risk_score, 10)
        severity = severity_from_score(risk_score)
        evidence_text = " ".join([indicator_type, value, *[v.status + " " + v.summary for v in verdicts]])
        mitre = map_to_mitre(indicator_type, evidence_text)
        mitre_text = " ".join(f"{m.tactic} {m.technique_id} {m.technique} {m.rationale}" for m in mitre)
        labels = threat_labels(value, indicator_type, list(verdicts), mitre_text)
        confidence = confidence_from_agreement(agreement, risk_score)
        related_entities = {}
        if item.parent:
            related_entities["parent_host"] = item.parent
        if item.host:
            related_entities["host"] = item.host
        return IndicatorResult(
            value=value,
            type=indicator_type,
            normalized_from=item.original_values,
            occurrence_count=item.occurrence_count,
            related_entities=related_entities,
            risk_score=risk_score,
            severity=severity,
            confidence=confidence,
            source_agreement=agreement,
            threat_labels=labels,
            verdicts=list(verdicts),
            mitre=mitre,
            recommended_actions=recommended_actions(indicator_type, severity, language, labels),
        )

    if normalized:
        results = await asyncio.gather(*(analyze_one(item) for item in normalized))

    summaries = local_summaries(company_name, results, language, raw_count)
    if use_openai:
        compact = [
            {
                "value": item.value,
                "type": item.type,
                "severity": item.severity,
                "confidence": item.confidence,
                "risk_score": item.risk_score,
                "source_agreement": item.source_agreement,
                "threat_labels": item.threat_labels,
                "sources": [v.model_dump(exclude={"raw"}) for v in item.verdicts],
                "mitre": [m.model_dump() for m in item.mitre],
            }
            for item in results
        ]
        ai = await summarize_with_openai(company_name, compact, context, language)
        if ai:
            summaries = ReportSummaries(**ai)

    stats = {
        "total": len(results),
        "submitted_count": raw_count,
        "deduplicated_count": raw_count - len(results),
        "by_severity": {level: sum(1 for item in results if item.severity == level) for level in ["Critical", "High", "Medium", "Low"]},
        "by_confidence": {level: sum(1 for item in results if item.confidence == level) for level in ["High", "Medium", "Low"]},
        "by_type": {kind: sum(1 for item in results if item.type == kind) for kind in ["ip", "domain", "url", "hash", "email", "unknown"]},
        "threat_labels": {
            label: sum(1 for item in results if label in item.threat_labels)
            for label in sorted({label for item in results for label in item.threat_labels})
        },
        "mitre": aggregate_mitre(results),
        "average_score": round(sum(item.risk_score for item in results) / len(results), 1) if results else 0,
    }
    analysis = AnalysisResult(
        id=str(uuid4()),
        company_name=company_name,
        language=language,
        created_at=datetime.utcnow(),
        indicators=results,
        summaries=summaries,
        stats=stats,
    )
    case_info = auto_case_for_analysis(analysis)
    analysis.case = case_info
    path = ANALYSES_DIR / f"{analysis.id}.json"
    path.write_text(json.dumps(analysis.model_dump(mode="json"), ensure_ascii=False, indent=2), encoding="utf-8")
    return analysis


def load_analysis(analysis_id: str) -> AnalysisResult:
    path = ANALYSES_DIR / f"{analysis_id}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return AnalysisResult(**data)


def list_analyses() -> list[dict[str, str]]:
    rows = []
    for path in sorted(ANALYSES_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        data = json.loads(path.read_text(encoding="utf-8"))
        rows.append(
            {
                "id": data["id"],
                "company_name": data.get("company_name", ""),
                "language": data.get("language", "ar"),
                "created_at": data.get("created_at", ""),
                "total": str(data.get("stats", {}).get("total", 0)),
                "average_score": str(data.get("stats", {}).get("average_score", 0)),
            }
        )
    return rows
