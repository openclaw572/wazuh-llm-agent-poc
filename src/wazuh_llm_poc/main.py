from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict

import yaml

from .alert_reader import get_high_risk_alerts
from .llm_analyzer import analyze_with_openai_compatible
from .policy_engine import evaluate_policy
from .response_agent import execute_actions, request_approval


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> int:
    parser = argparse.ArgumentParser(description="Wazuh LLM Alert Analyzer + Policy-gated Response Agent PoC")
    parser.add_argument("--config", default="config/poc.yaml")
    parser.add_argument("--alerts", help="Override alerts.json path")
    parser.add_argument("--once", action="store_true", help="Process current high-risk alerts once")
    args = parser.parse_args()

    cfg = load_config(args.config)
    alerts_path = args.alerts or cfg["wazuh"]["alerts_path"]
    min_level = int(cfg["wazuh"].get("min_rule_level", 10))
    limit = int(cfg["wazuh"].get("limit", 20))

    summaries = get_high_risk_alerts(alerts_path, min_level=min_level, limit=limit)
    output_records = []

    for summary in summaries:
        verdict = analyze_with_openai_compatible(summary, cfg.get("llm", {}))
        decision = evaluate_policy(verdict, cfg.get("policy", {}))
        approved = request_approval(decision.allowed_actions, cfg.get("approval", {}).get("mode", "file"), cfg.get("approval", {}).get("file"))
        if approved:
            response = execute_actions(decision.allowed_actions, cfg.get("runtime", {}))
        else:
            response = execute_actions(
                [a for a in decision.allowed_actions if a.get("type") in {"notify_admin", "create_incident"}],
                cfg.get("runtime", {}),
            )
            for a in decision.allowed_actions:
                if a.get("type") not in {"notify_admin", "create_incident"}:
                    response.skipped.append({**a, "status": "waiting_for_admin_approval"})

        output_records.append({
            "alert": asdict(summary),
            "llm_verdict": asdict(verdict),
            "policy_decision": asdict(decision),
            "admin_approved": approved,
            "response_result": asdict(response),
        })

    print(json.dumps(output_records, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
