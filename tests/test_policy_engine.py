from wazuh_llm_poc.models import LLMVerdict
from wazuh_llm_poc.policy_engine import evaluate_policy


def test_policy_denies_low_confidence_active_defense_but_allows_notify():
    verdict = LLMVerdict(
        false_positive_likelihood="medium",
        risk_level="high",
        reason="test",
        needs_defense=True,
        recommended_actions=[
            {"type": "notify_admin", "target": "admin", "reason": "review"},
            {"type": "block_ip", "target": "8.8.8.8", "reason": "bad"},
        ],
        confidence=0.5,
    )
    decision = evaluate_policy(verdict, {
        "allowed_action_types": ["notify_admin", "block_ip"],
        "min_confidence_for_defense": 0.7,
        "require_human_approval": True,
        "allow_private_ip_block": False,
        "allow_defense_for_risk_levels": ["high", "critical"],
    })
    assert [a["type"] for a in decision.allowed_actions] == ["notify_admin"]
    assert decision.denied_actions[0]["type"] == "block_ip"


def test_policy_denies_private_ip_block_by_default():
    verdict = LLMVerdict("low", "critical", "test", True, [{"type": "block_ip", "target": "192.168.1.10", "reason": "bad"}], 0.9)
    decision = evaluate_policy(verdict, {
        "allowed_action_types": ["block_ip"],
        "min_confidence_for_defense": 0.7,
        "require_human_approval": True,
        "allow_private_ip_block": False,
        "allow_defense_for_risk_levels": ["high", "critical"],
    })
    assert not decision.allowed_actions
    assert decision.denied_actions
