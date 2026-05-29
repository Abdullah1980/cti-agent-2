import json
import sqlite3
import time
from datetime import datetime
from typing import Any

from app.core.config import DB_PATH
from app.core.models import AnalysisResult


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def execute_with_retry(operation, attempts: int = 5, delay: float = 0.4):
    last_error = None
    for attempt in range(attempts):
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" not in str(exc).lower() or attempt == attempts - 1:
                raise
            time.sleep(delay * (attempt + 1))
    if last_error:
        raise last_error


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                category TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                auto_created INTEGER NOT NULL DEFAULT 1,
                notes TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                case_id TEXT,
                company_name TEXT NOT NULL,
                language TEXT NOT NULL,
                created_at TEXT NOT NULL,
                average_score REAL NOT NULL,
                total_iocs INTEGER NOT NULL,
                high_critical INTEGER NOT NULL,
                high_confidence INTEGER NOT NULL,
                raw_json TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                case_id TEXT,
                value TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                threat_labels TEXT NOT NULL,
                source_agreement TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                FOREIGN KEY(analysis_id) REFERENCES analyses(id),
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS case_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                title TEXT NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS case_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );

            CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
            CREATE INDEX IF NOT EXISTS idx_indicators_case ON indicators(case_id);
            CREATE INDEX IF NOT EXISTS idx_analyses_case ON analyses(case_id);
            CREATE INDEX IF NOT EXISTS idx_case_tasks_case ON case_tasks(case_id);
            CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events(case_id);
            """
        )


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def priority_from_analysis(analysis: AnalysisResult) -> str:
    high_critical = analysis.stats.get("by_severity", {}).get("Critical", 0) + analysis.stats.get("by_severity", {}).get("High", 0)
    high_conf = analysis.stats.get("by_confidence", {}).get("High", 0)
    avg = analysis.stats.get("average_score", 0)
    if analysis.stats.get("by_severity", {}).get("Critical", 0) >= 3 or high_conf >= 5 or avg >= 80:
        return "Critical"
    if high_critical >= 2 or avg >= 60:
        return "High"
    if high_critical == 1 or avg >= 30:
        return "Medium"
    return "Low"


def category_from_labels(labels: dict[str, int]) -> str:
    if labels.get("payload-delivery", 0) or labels.get("malware", 0):
        return "Malware Delivery"
    if labels.get("c2", 0) or labels.get("possible-c2", 0):
        return "Command and Control"
    if labels.get("phishing", 0) or labels.get("possible-phishing", 0):
        return "Phishing"
    if labels.get("abuse-reported", 0):
        return "Abuse Infrastructure"
    return "IOC Investigation"


def should_create_case(analysis: AnalysisResult) -> bool:
    priority = priority_from_analysis(analysis)
    high_conf = analysis.stats.get("by_confidence", {}).get("High", 0)
    harmful = analysis.stats.get("by_severity", {}).get("Critical", 0) + analysis.stats.get("by_severity", {}).get("High", 0)
    return priority in {"Critical", "High"} or high_conf >= 2 or harmful >= 2


def find_existing_case(conn: sqlite3.Connection, analysis: AnalysisResult) -> dict[str, Any] | None:
    values = [item.value for item in analysis.indicators]
    if not values:
        return None
    placeholders = ",".join("?" for _ in values)
    row = conn.execute(
        f"""
        SELECT c.*
        FROM cases c
        JOIN indicators i ON i.case_id = c.id
        WHERE c.status != 'Closed' AND i.value IN ({placeholders})
        GROUP BY c.id
        ORDER BY COUNT(*) DESC, c.updated_at DESC
        LIMIT 1
        """,
        values,
    ).fetchone()
    return row_to_dict(row) if row else None


def create_case(conn: sqlite3.Connection, analysis: AnalysisResult) -> dict[str, Any]:
    now = datetime.utcnow().isoformat()
    labels = analysis.stats.get("threat_labels", {})
    category = category_from_labels(labels)
    priority = priority_from_analysis(analysis)
    case_id = f"case-{analysis.id[:8]}"
    reason = (
        f"Auto-created from analysis {analysis.id}: "
        f"{analysis.stats.get('by_severity', {}).get('Critical', 0)} Critical, "
        f"{analysis.stats.get('by_confidence', {}).get('High', 0)} High-confidence indicators, "
        f"labels={', '.join(sorted(labels.keys())) or 'none'}."
    )
    name = f"Auto Case - {category} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
    conn.execute(
        """
        INSERT INTO cases (id, name, status, priority, category, reason, created_at, updated_at, auto_created)
        VALUES (?, ?, 'Open', ?, ?, ?, ?, ?, 1)
        """,
        (case_id, name, priority, category, reason, now, now),
    )
    conn.execute(
        "INSERT INTO case_events (case_id, event_type, message, created_at) VALUES (?, 'created', ?, ?)",
        (case_id, reason, now),
    )
    ensure_case_tasks(conn, case_id, category)
    return get_case_by_id(conn, case_id) or {"id": case_id, "name": name, "priority": priority, "category": category, "status": "Open", "reason": reason}


def get_case_by_id(conn: sqlite3.Connection, case_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    return row_to_dict(row) if row else None


def save_analysis(analysis: AnalysisResult, case_info: dict[str, Any] | None) -> None:
    def operation() -> None:
        case_id = case_info["id"] if case_info else None
        high_critical = analysis.stats.get("by_severity", {}).get("Critical", 0) + analysis.stats.get("by_severity", {}).get("High", 0)
        high_conf = analysis.stats.get("by_confidence", {}).get("High", 0)
        with connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO analyses
                (id, case_id, company_name, language, created_at, average_score, total_iocs, high_critical, high_confidence, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis.id,
                    case_id,
                    analysis.company_name,
                    analysis.language,
                    analysis.created_at.isoformat(),
                    analysis.stats.get("average_score", 0),
                    analysis.stats.get("total", 0),
                    high_critical,
                    high_conf,
                    json.dumps(analysis.model_dump(mode="json"), ensure_ascii=False),
                ),
            )
            for item in analysis.indicators:
                conn.execute(
                    """
                    INSERT INTO indicators
                    (analysis_id, case_id, value, type, severity, confidence, risk_score, threat_labels, source_agreement, first_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        analysis.id,
                        case_id,
                        item.value,
                        item.type,
                        item.severity,
                        item.confidence,
                        item.risk_score,
                        json.dumps(item.threat_labels),
                        json.dumps(item.source_agreement),
                        analysis.created_at.isoformat(),
                    ),
                )
            if case_id:
                conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (datetime.utcnow().isoformat(), case_id))
                conn.execute(
                    "INSERT INTO case_events (case_id, event_type, message, created_at) VALUES (?, 'analysis_linked', ?, ?)",
                    (case_id, f"Linked analysis {analysis.id} with {analysis.stats.get('total', 0)} unique indicators.", datetime.utcnow().isoformat()),
                )

    execute_with_retry(operation)


def checklist_for_category(category: str) -> list[str]:
    common = [
        "Validate source agreement and confidence.",
        "Search SIEM, EDR, DNS, proxy, and firewall telemetry.",
        "Document business impact and affected assets.",
    ]
    if category == "Malware Delivery":
        return [
            "Block malicious URLs, IPs, and hashes on defensive controls.",
            "Hunt for payload download and execution evidence.",
            "Collect suspicious files for malware analysis.",
        ] + common
    if category == "Command and Control":
        return [
            "Block suspected C2 destinations.",
            "Hunt for beaconing, unusual ports, and long-lived sessions.",
            "Isolate hosts with confirmed outbound C2 activity.",
        ] + common
    if category == "Phishing":
        return [
            "Block URLs/domains across email and web controls.",
            "Search mailboxes for matching sender, subject, and URL patterns.",
            "Reset credentials for users who interacted with the lure.",
        ] + common
    if category == "Abuse Infrastructure":
        return [
            "Review external exposure and inbound attempts.",
            "Add high-confidence infrastructure to watchlists.",
            "Correlate abuse reports with internal telemetry.",
        ] + common
    return [
        "Triage each IOC and confirm source quality.",
        "Escalate high-confidence or high-severity indicators.",
        "Create containment actions for confirmed matches.",
    ] + common


def ensure_case_tasks(conn: sqlite3.Connection, case_id: str, category: str) -> None:
    existing = conn.execute("SELECT COUNT(*) AS total FROM case_tasks WHERE case_id = ?", (case_id,)).fetchone()
    if existing and existing["total"]:
        return
    now = datetime.utcnow().isoformat()
    for title in checklist_for_category(category):
        conn.execute(
            "INSERT INTO case_tasks (case_id, title, completed, created_at, updated_at) VALUES (?, ?, 0, ?, ?)",
            (case_id, title, now, now),
        )


def auto_case_for_analysis(analysis: AnalysisResult) -> dict[str, Any]:
    init_db()

    def operation() -> dict[str, Any]:
        with connect() as conn:
            existing = find_existing_case(conn, analysis)
            if existing:
                return existing | {"linked_by": "matching_ioc"}
            if should_create_case(analysis):
                return create_case(conn, analysis) | {"linked_by": "auto_created"}
            return {
                "id": None,
                "status": "No Case",
                "priority": priority_from_analysis(analysis),
                "category": category_from_labels(analysis.stats.get("threat_labels", {})),
                "reason": "Analysis did not meet automatic case creation thresholds.",
                "linked_by": "none",
            }

    case_info = execute_with_retry(operation)
    save_analysis(analysis, case_info if case_info.get("id") else None)
    return case_info


def list_cases() -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT c.*,
                   COUNT(DISTINCT a.id) AS analysis_count,
                   COUNT(i.id) AS indicator_count
            FROM cases c
            LEFT JOIN analyses a ON a.case_id = c.id
            LEFT JOIN indicators i ON i.case_id = c.id
            GROUP BY c.id
            ORDER BY c.updated_at DESC
            """
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def get_case(case_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        case = get_case_by_id(conn, case_id)
        if not case:
            return None
        ensure_case_tasks(conn, case_id, case["category"])
        analyses = [row_to_dict(row) for row in conn.execute("SELECT id, created_at, average_score, total_iocs, high_critical, high_confidence FROM analyses WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()]
        indicators = [row_to_dict(row) for row in conn.execute("SELECT value, type, severity, confidence, risk_score, threat_labels FROM indicators WHERE case_id = ? ORDER BY risk_score DESC", (case_id,)).fetchall()]
        tasks = [row_to_dict(row) for row in conn.execute("SELECT id, title, completed, created_at, updated_at FROM case_tasks WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()]
        events = [row_to_dict(row) for row in conn.execute("SELECT id, event_type, message, created_at FROM case_events WHERE case_id = ? ORDER BY created_at DESC, id DESC", (case_id,)).fetchall()]
        case["analyses"] = analyses
        case["indicators"] = indicators
        case["tasks"] = tasks
        case["timeline"] = events
        return case


def update_case(case_id: str, status: str | None = None, notes: str | None = None, tasks: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    init_db()

    def operation() -> bool:
        with connect() as conn:
            case = get_case_by_id(conn, case_id)
            if not case:
                return False
            now = datetime.utcnow().isoformat()
            if status and status != case["status"]:
                conn.execute("UPDATE cases SET status = ?, updated_at = ? WHERE id = ?", (status, now, case_id))
                conn.execute(
                    "INSERT INTO case_events (case_id, event_type, message, created_at) VALUES (?, 'status_changed', ?, ?)",
                    (case_id, f"Status changed from {case['status']} to {status}.", now),
                )
            if notes is not None and notes != case["notes"]:
                conn.execute("UPDATE cases SET notes = ?, updated_at = ? WHERE id = ?", (notes, now, case_id))
                conn.execute(
                    "INSERT INTO case_events (case_id, event_type, message, created_at) VALUES (?, 'notes_updated', 'Analyst notes updated.', ?)",
                    (case_id, now),
                )
            for task in tasks or []:
                task_id = int(task["id"])
                completed = 1 if task.get("completed") else 0
                old = conn.execute("SELECT title, completed FROM case_tasks WHERE id = ? AND case_id = ?", (task_id, case_id)).fetchone()
                if old and old["completed"] != completed:
                    conn.execute("UPDATE case_tasks SET completed = ?, updated_at = ? WHERE id = ? AND case_id = ?", (completed, now, task_id, case_id))
                    state = "completed" if completed else "reopened"
                    conn.execute(
                        "INSERT INTO case_events (case_id, event_type, message, created_at) VALUES (?, 'task_updated', ?, ?)",
                        (case_id, f"Task {state}: {old['title']}", now),
                    )
            return True

    updated = execute_with_retry(operation)
    return get_case(case_id) if updated else None
