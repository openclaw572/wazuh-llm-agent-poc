from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List

from .models import LLMVerdict, PolicyDecision

PRIVATE_OR_RESERVED = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def _is_blockable_ip(value: str, allow_private: bool) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if allow_private:
        return True
    return not any(ip in net for net in PRIVATE_OR_RESERVED)


def evaluate_policy(verdict: LLMVerdict, policy: Dict[str, Any]) -> PolicyDecision:
    decision = PolicyDecision()
    allowed_types = set(policy.get("allowed_action_types", []))
    min_conf = float(policy.get("min_confidence_for_defense", 0.7))
    require_human = bool(policy.get("require_human_approval", True))
    allow_private_ip_block = bool(policy.get("allow_private_ip_block", False))
    max_risk_actions = set(policy.get("allow_defense_for_risk_levels", ["high", "critical"]))

    if not verdict.needs_defense:
        decision.reasons.append("LLM verdict says no defense needed")
        return decision
    if verdict.risk_level not in max_risk_actions:
        decision.reasons.append(f"Risk level {verdict.risk_level} is below policy threshold")
        return decision
    if verdict.confidence < min_conf:
        decision.reasons.append(f"Confidence {verdict.confidence} below policy min {min_conf}")
        # Notify and incident can still be allowed even when active defense is denied.

    for action in verdict.recommended_actions:
        typ = action.get("type")
        target = str(action.get("target", ""))
        deny_reason = None
        if typ not in allowed_types:
            deny_reason = f"Action type {typ} is not in allow-list"
        elif typ in {"block_ip", "quarantine_file", "kill_process", "disable_account"} and verdict.confidence < min_conf:
            deny_reason = "Active defense denied due to low confidence"
        elif typ == "block_ip" and not _is_blockable_ip(target, allow_private_ip_block):
            deny_reason = f"IP target {target} is invalid, private, loopback, or reserved"

        action_with_gate = dict(action)
        action_with_gate["requires_human_approval"] = require_human
        if deny_reason:
            action_with_gate["deny_reason"] = deny_reason
            decision.denied_actions.append(action_with_gate)
        else:
            decision.allowed_actions.append(action_with_gate)

    return decision
