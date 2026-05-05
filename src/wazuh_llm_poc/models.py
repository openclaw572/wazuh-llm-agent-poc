from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AlertSummary:
    rule_id: str
    rule_level: int
    rule_description: str
    agent_name: str
    agent_id: str
    srcip: Optional[str]
    user: Optional[str]
    process: Optional[str]
    file_path: Optional[str]
    timestamp: Optional[str]
    raw: Dict[str, Any]


@dataclass
class LLMVerdict:
    false_positive_likelihood: str
    risk_level: str
    reason: str
    needs_defense: bool
    recommended_actions: List[Dict[str, Any]]
    confidence: float


@dataclass
class PolicyDecision:
    allowed_actions: List[Dict[str, Any]] = field(default_factory=list)
    denied_actions: List[Dict[str, Any]] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


@dataclass
class ResponseResult:
    executed: List[Dict[str, Any]] = field(default_factory=list)
    skipped: List[Dict[str, Any]] = field(default_factory=list)
