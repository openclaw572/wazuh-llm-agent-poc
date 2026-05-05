from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .models import AlertSummary


def iter_alerts(alerts_path: str | Path) -> Iterable[Dict[str, Any]]:
    """Read Wazuh alerts.json where each line is one JSON object."""
    path = Path(alerts_path)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def nested_get(data: Dict[str, Any], dotted: str, default=None):
    cur: Any = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def summarize_alert(alert: Dict[str, Any]) -> AlertSummary:
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    win = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
    eventdata = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}

    srcip = (
        nested_get(alert, "data.srcip")
        or nested_get(alert, "data.src_ip")
        or nested_get(alert, "data.win.eventdata.ipAddress")
        or nested_get(alert, "data.win.eventdata.sourceIp")
    )
    user = (
        nested_get(alert, "data.dstuser")
        or nested_get(alert, "data.srcuser")
        or eventdata.get("targetUserName")
        or eventdata.get("subjectUserName")
    )
    process = eventdata.get("image") or eventdata.get("processName") or nested_get(alert, "data.process.name")
    file_path = eventdata.get("targetFilename") or nested_get(alert, "syscheck.path") or nested_get(alert, "data.file")

    return AlertSummary(
        rule_id=str(nested_get(alert, "rule.id", "unknown")),
        rule_level=int(nested_get(alert, "rule.level", 0) or 0),
        rule_description=str(nested_get(alert, "rule.description", "")),
        agent_name=str(nested_get(alert, "agent.name", "unknown")),
        agent_id=str(nested_get(alert, "agent.id", "unknown")),
        srcip=srcip,
        user=user,
        process=process,
        file_path=file_path,
        timestamp=alert.get("timestamp"),
        raw=alert,
    )


def get_high_risk_alerts(alerts_path: str | Path, min_level: int = 10, limit: int = 20) -> List[AlertSummary]:
    results: List[AlertSummary] = []
    for alert in iter_alerts(alerts_path):
        summary = summarize_alert(alert)
        if summary.rule_level >= min_level:
            results.append(summary)
            if len(results) >= limit:
                break
    return results
