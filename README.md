# Wazuh LLM Alert Analyzer + AI Response Agent PoC

A minimal, repeatable PoC for an intelligent security detection and response workflow:

```text
[Endpoint / Local Machine]
    ↓
Wazuh Agent detects local security events
    ↓
[Wazuh Manager / Wazuh Dashboard]
    ↓
Wazuh decoder/rules generate alerts
    ↓
/var/ossec/logs/alerts/alerts.json
    ↓
[LLM Analyzer Service]
    ↓
Risk / false-positive / response recommendation JSON
    ↓
[Policy Engine]
    ↓
Allow-list + confidence + target validation + human approval gate
    ↓
[AI Response Agent]
    ↓
Notify admin / create incident / dry-run block IP / log high-impact actions
```

## What This PoC Demonstrates

1. Wazuh Agent detects endpoint events.
2. Wazuh Manager stores high-risk alerts in `alerts.json` and Dashboard displays them.
3. Python service reads Wazuh alert JSON lines.
4. High-risk events are sent to an OpenAI-compatible LLM analyzer.
5. The LLM returns a strict JSON verdict:
   - false-positive likelihood
   - risk level
   - attack or anomaly reason
   - whether defense is needed
   - recommended defense actions
   - confidence score
6. Policy Engine prevents unrestricted LLM command execution.
7. Admin approval is required before active defense.
8. Response Agent performs safe response actions or dry-runs active defense.

## Safety Model

The LLM is never allowed to execute commands directly.

```text
LLM output -> structured JSON only
Policy Engine -> validates whether action is allowed
Admin approval -> required for active defense
Response Agent -> executes only approved/policy-allowed actions
```

Default safe settings:

```yaml
policy:
  require_human_approval: true
  min_confidence_for_defense: 0.70

runtime:
  dry_run: true
```

High-impact actions such as `quarantine_file`, `kill_process`, and `disable_account` are logged only in this PoC. Production usage should connect those to audited EDR/SOAR APIs.

## Repository Layout

```text
.
├── .github/workflows/ci.yml
├── .gitignore
├── README.md
├── config/poc.yaml
├── docs/
│   ├── OBSERVE.md
│   ├── TASK_LOG.md
│   └── implementation-plan.md
├── pyproject.toml
├── samples/alerts.json
├── src/wazuh_llm_poc/
│   ├── __init__.py
│   ├── alert_reader.py
│   ├── llm_analyzer.py
│   ├── main.py
│   ├── models.py
│   ├── policy_engine.py
│   └── response_agent.py
└── tests/
    ├── test_alert_reader.py
    └── test_policy_engine.py
```

## Components

| Component | File | Purpose |
|---|---|---|
| Alert Reader | `src/wazuh_llm_poc/alert_reader.py` | Reads Wazuh JSONL alerts and extracts high-risk summaries. |
| LLM Analyzer | `src/wazuh_llm_poc/llm_analyzer.py` | Uses OpenAI-compatible API or offline heuristic fallback. |
| Models | `src/wazuh_llm_poc/models.py` | Dataclasses for alert, verdict, policy decision, and response result. |
| Policy Engine | `src/wazuh_llm_poc/policy_engine.py` | Enforces action allow-list, confidence threshold, and target safety. |
| Response Agent | `src/wazuh_llm_poc/response_agent.py` | Logs incidents and executes/dry-runs allowed response actions. |
| CLI | `src/wazuh_llm_poc/main.py` | End-to-end command-line entrypoint. |

## Quick Start with Sample Data

```bash
git clone https://github.com/openclaw572/wazuh-llm-agent-poc.git
cd wazuh-llm-agent-poc
python3 -m venv .venv
. .venv/bin/activate
pip install -e . pytest
pytest -q
wazuh-llm-poc --config config/poc.yaml --alerts samples/alerts.json --once
```

Expected test result:

```text
3 passed
```

Expected PoC behavior:

- Rule level 12 SSH alert is analyzed.
- Rule level 14 file integrity alert is analyzed.
- Policy allows `notify_admin` and `create_incident`.
- Active defense is denied or skipped unless confidence and approval requirements are met.

## Wazuh Manager / Dashboard Setup

For a single-host lab, use the Wazuh all-in-one installer:

```bash
curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

After installation, record the Dashboard URL and credentials printed by the installer.

Verify Manager alerts:

```bash
sudo systemctl status wazuh-manager --no-pager
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

## Wazuh Agent Setup

Ubuntu/Debian endpoint example. Replace `WAZUH_MANAGER_IP` with your Wazuh Manager IP:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
printf 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n' | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo WAZUH_MANAGER='WAZUH_MANAGER_IP' apt-get install wazuh-agent -y
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent --no-pager
```

Then verify in Wazuh Dashboard that the agent is connected.

## Generate Test Security Events

### SSH Authentication Failure

From another host:

```bash
ssh wronguser@ENDPOINT_IP
# enter a wrong password several times
```

Observe the event in:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

And in Wazuh Dashboard under Security events.

### File Integrity Event

On the endpoint, add a test syscheck directory to Wazuh Agent config:

```xml
<syscheck>
  <directories realtime="yes">/tmp/wazuh-poc</directories>
</syscheck>
```

Restart and create a test file:

```bash
sudo mkdir -p /tmp/wazuh-poc
sudo systemctl restart wazuh-agent
sudo sh -c 'echo suspicious > /tmp/wazuh-poc/test.txt'
```

## Connect PoC to Real Wazuh alerts.json

On the Wazuh Manager host:

```bash
sudo setfacl -m u:$USER:r /var/ossec/logs/alerts/alerts.json
cd /path/to/wazuh-llm-agent-poc
. .venv/bin/activate
wazuh-llm-poc --config config/poc.yaml --once
```

If you do not want to change ACLs:

```bash
sudo .venv/bin/wazuh-llm-poc --config config/poc.yaml --once
```

## LLM Configuration

If no API key is configured, the PoC uses an offline heuristic analyzer so the pipeline can still be tested.

To use a real OpenAI-compatible LLM:

```bash
export OPENAI_API_KEY='your-api-key'
export OPENAI_MODEL='gpt-4o-mini'
```

For local or self-hosted OpenAI-compatible APIs:

```bash
export OPENAI_BASE_URL='http://localhost:8000/v1'
export OPENAI_API_KEY='dummy-or-real-key'
export OPENAI_MODEL='your-model-name'
```

You can also set these in `config/poc.yaml`, but environment variables are safer for secrets.

## Admin Approval

Default mode is file approval:

```yaml
approval:
  mode: file
  file: /tmp/wazuh-llm-poc/APPROVE
```

Without approval:

```bash
rm -f /tmp/wazuh-llm-poc/APPROVE
wazuh-llm-poc --config config/poc.yaml --alerts samples/alerts.json --once
```

With approval:

```bash
echo APPROVE > /tmp/wazuh-llm-poc/APPROVE
wazuh-llm-poc --config config/poc.yaml --alerts samples/alerts.json --once
rm -f /tmp/wazuh-llm-poc/APPROVE
```

Interactive approval is also supported:

```yaml
approval:
  mode: interactive
```

## Response Actions

| Action | PoC Behavior |
|---|---|
| `notify_admin` | Append JSONL record to incident log. |
| `create_incident` | Append JSONL record to incident log. |
| `block_ip` | Generates or executes configured firewall command. Default is dry-run. |
| `quarantine_file` | Logged only; not executed in PoC. |
| `kill_process` | Logged only; not executed in PoC. |
| `disable_account` | Logged only; not executed in PoC. |

Incident log path:

```text
/tmp/wazuh-llm-poc/incidents.jsonl
```

## How to Observe the Whole Process

See [`docs/OBSERVE.md`](docs/OBSERVE.md) for a terminal-by-terminal observation guide.

Short version:

Terminal 1, endpoint:

```bash
sudo journalctl -u wazuh-agent -f
```

Terminal 2, Wazuh Manager:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

Terminal 3, PoC host:

```bash
touch /tmp/wazuh-llm-poc/incidents.jsonl
tail -f /tmp/wazuh-llm-poc/incidents.jsonl
```

Terminal 4, PoC host:

```bash
wazuh-llm-poc --config config/poc.yaml --once
```

Then trigger SSH failures or file integrity changes on the endpoint and compare:

- Wazuh Dashboard event
- `alerts.json` line
- analyzer stdout JSON
- `policy_decision`
- `incidents.jsonl`

## Enable Real IP Blocking Only in an Isolated Lab

Default is safe dry-run:

```yaml
runtime:
  dry_run: true
```

To enable real blocking, change:

```yaml
runtime:
  dry_run: false
```

Before doing so:

```bash
iptables -S
ip route
who
```

Make sure you have console access and are not blocking your own management IP.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e . pytest
pytest -q
```

Run sample flow:

```bash
wazuh-llm-poc --config config/poc.yaml --alerts samples/alerts.json --once
```

## CI

GitHub Actions runs:

1. Package install.
2. Unit tests on Python 3.10, 3.11, and 3.12.
3. Sample PoC CLI flow.

Workflow file:

```text
.github/workflows/ci.yml
```

## Production Hardening Ideas

This is intentionally an MVP. Before production use, add:

1. Persistent event deduplication and cursor tracking.
2. SQLite/PostgreSQL incident store.
3. Dashboard/API for approvals.
4. Slack/Discord/Email approval notifications.
5. Wazuh API enrichment for agent metadata.
6. SOAR/EDR integration for quarantine/kill/disable actions.
7. Correlation rules before active blocking.
8. Signed audit trail for response actions.
9. Role-based approval and break-glass workflow.
10. Canary allow-list to prevent blocking management infrastructure.

## License

MIT or internal PoC use, depending on your organization policy.
