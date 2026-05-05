from wazuh_llm_poc.alert_reader import get_high_risk_alerts


def test_get_high_risk_alerts_filters_by_level():
    alerts = get_high_risk_alerts("samples/alerts.json", min_level=10)
    assert len(alerts) == 2
    assert alerts[0].srcip == "203.0.113.10"
    assert alerts[1].file_path == "/tmp/eicar.com"
