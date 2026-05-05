# PoC Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task if expanding beyond the MVP.

**Goal:** Build a minimal Wazuh alert analysis and response workflow with LLM judgment, policy gating, and admin approval.

**Architecture:** Wazuh Agent forwards local events to Wazuh Manager; Manager writes `alerts.json`; Python service reads high-risk alerts, sends summaries to an OpenAI-compatible LLM, evaluates actions against policy, asks for admin approval, then logs or dry-runs response actions.

**Tech Stack:** Wazuh 4.x, Python 3.10+, PyYAML, requests, pytest, Linux iptables/nftables.

---

## Task 1: Verify Wazuh Manager and Dashboard

**Objective:** Confirm the server produces alerts and the dashboard shows them.

**Commands:**

```bash
sudo systemctl status wazuh-manager --no-pager
sudo tail -n 5 /var/ossec/logs/alerts/alerts.json
```

**Expected:** Manager active and JSON alert lines visible.

## Task 2: Register and verify Wazuh Agent

**Objective:** Endpoint connects and sends security events.

**Commands:**

```bash
sudo systemctl status wazuh-agent --no-pager
sudo /var/ossec/bin/agent_control -l
```

**Expected:** Agent status Active in Manager/Dashboard.

## Task 3: Run the analyzer against samples

**Objective:** Validate PoC logic without touching production controls.

**Commands:**

```bash
cd /tmp/wazuh-llm-poc
. .venv/bin/activate
pytest -q
wazuh-llm-poc --config config/poc.yaml --alerts samples/alerts.json --once
```

**Expected:** Tests pass; output includes verdict, policy decision, and skipped active defense pending approval.

## Task 4: Run analyzer against real alerts

**Objective:** Analyze real high-risk alerts from Wazuh Manager.

**Commands:**

```bash
sudo setfacl -m u:$USER:r /var/ossec/logs/alerts/alerts.json
wazuh-llm-poc --config /tmp/wazuh-llm-poc/config/poc.yaml --once
```

**Expected:** High-risk Wazuh alerts are summarized and analyzed.

## Task 5: Enable approval-gated response

**Objective:** Allow only policy-approved actions after manager approval.

**Commands:**

```bash
echo APPROVE > /tmp/wazuh-llm-poc/APPROVE
wazuh-llm-poc --config /tmp/wazuh-llm-poc/config/poc.yaml --once
rm /tmp/wazuh-llm-poc/APPROVE
```

**Expected:** notify/create incident actions logged; block_ip remains dry-run unless explicitly configured.
