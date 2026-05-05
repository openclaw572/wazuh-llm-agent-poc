from __future__ import annotations

import json
import os
import re
from dataclasses import asdict
from typing import Any, Dict

import requests

from .models import AlertSummary, LLMVerdict

SYSTEM_PROMPT = """You are a senior SOC analyst. Analyze a Wazuh alert.
Return ONLY valid JSON with this schema:
{
  "false_positive_likelihood": "low|medium|high",
  "risk_level": "low|medium|high|critical",
  "reason": "short explanation",
  "needs_defense": true,
  "recommended_actions": [
    {"type":"notify_admin|create_incident|block_ip|quarantine_file|kill_process|disable_account", "target":"...", "reason":"..."}
  ],
  "confidence": 0.0
}
Never recommend destructive action unless the alert contains concrete target evidence.
"""


def _extract_json(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, flags=re.S)
        if not m:
            raise
        return json.loads(m.group(0))


def heuristic_analyze(alert: AlertSummary) -> LLMVerdict:
    """Fallback analyzer for offline PoC/demo when no LLM API key is configured."""
    desc = alert.rule_description.lower()
    actions = [{"type": "notify_admin", "target": "security-admin", "reason": "High-risk Wazuh alert requires human review"},
               {"type": "create_incident", "target": f"wazuh-rule-{alert.rule_id}", "reason": "Create audit trail"}]
    risk = "high" if alert.rule_level < 13 else "critical"
    false_positive = "medium"
    reason = f"Rule level {alert.rule_level}: {alert.rule_description}"

    if alert.srcip and any(k in desc for k in ["sshd", "authentication", "failed", "brute", "attack"]):
        actions.append({"type": "block_ip", "target": alert.srcip, "reason": "Source IP associated with high-risk auth alert"})
        false_positive = "low"
    if alert.file_path and any(k in desc for k in ["malware", "trojan", "virus", "integrity"]):
        actions.append({"type": "quarantine_file", "target": alert.file_path, "reason": "Suspicious file path present in high-risk alert"})
    if alert.process and any(k in desc for k in ["malware", "suspicious process", "persistence"]):
        actions.append({"type": "kill_process", "target": alert.process, "reason": "Suspicious process present in high-risk alert"})

    return LLMVerdict(false_positive, risk, reason, True, actions, 0.62)


def analyze_with_openai_compatible(alert: AlertSummary, config: Dict[str, Any]) -> LLMVerdict:
    base_url = config.get("base_url") or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    api_key = config.get("api_key") or os.getenv("OPENAI_API_KEY")
    model = config.get("model") or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    if not api_key:
        return heuristic_analyze(alert)

    payload = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(asdict(alert), ensure_ascii=False)[:12000]},
        ],
        "response_format": {"type": "json_object"},
    }
    resp = requests.post(
        f"{base_url.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=60,
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    data = _extract_json(content)
    return LLMVerdict(
        false_positive_likelihood=data["false_positive_likelihood"],
        risk_level=data["risk_level"],
        reason=data["reason"],
        needs_defense=bool(data["needs_defense"]),
        recommended_actions=list(data.get("recommended_actions", [])),
        confidence=float(data.get("confidence", 0.0)),
    )
