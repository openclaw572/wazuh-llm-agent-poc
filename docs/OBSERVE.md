# How to Observe the PoC End-to-End

This guide explains how to actually watch the Wazuh + LLM + AI Response Agent flow while it is running.

## Observation Points

```text
[1] Endpoint local activity
    ↓
[2] Wazuh Agent log
    ↓
[3] Wazuh Manager alerts.json
    ↓
[4] Wazuh Dashboard
    ↓
[5] PoC analyzer stdout JSON
    ↓
[6] Policy decision
    ↓
[7] Admin approval file / prompt
    ↓
[8] Incident log / dry-run response command
```

## Terminal Layout

Use 4 terminals if possible.

### Terminal 1: Watch Wazuh Agent on endpoint

On the endpoint with Wazuh Agent installed:

```bash
sudo journalctl -u wazuh-agent -f
```

You should see the agent running and forwarding events.

### Terminal 2: Watch Wazuh Manager alerts

On the Wazuh Manager:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

When a matching event happens, a JSON alert line should appear.

### Terminal 3: Watch incident log from this PoC

On the host running the PoC:

```bash
touch /tmp/wazuh-llm-poc/incidents.jsonl
tail -f /tmp/wazuh-llm-poc/incidents.jsonl
```

You should see JSONL records when `notify_admin`, `create_incident`, or dry-run response actions are processed.

### Terminal 4: Run the analyzer

For sample data:

```bash
cd /tmp/wazuh-llm-poc
. .venv/bin/activate
wazuh-llm-poc --config config/poc.yaml --alerts samples/alerts.json --once
```

For real Wazuh alerts:

```bash
cd /tmp/wazuh-llm-poc
. .venv/bin/activate
wazuh-llm-poc --config config/poc.yaml --once
```

## Generate Test Events

### SSH failed login event

From another host:

```bash
ssh wronguser@ENDPOINT_IP
# enter the wrong password several times
```

Observe:

1. Endpoint auth log receives failed SSH event.
2. Wazuh Agent forwards the event.
3. Wazuh Manager writes an alert to `alerts.json`.
4. Wazuh Dashboard shows the alert.
5. PoC analyzer produces an LLM verdict and policy decision.

### File integrity event

On the endpoint, configure Wazuh syscheck for a test directory:

```xml
<syscheck>
  <directories realtime="yes">/tmp/wazuh-poc</directories>
</syscheck>
```

Restart the agent:

```bash
sudo mkdir -p /tmp/wazuh-poc
sudo systemctl restart wazuh-agent
sudo sh -c 'echo suspicious > /tmp/wazuh-poc/test.txt'
```

Observe the same pipeline through Manager, Dashboard, analyzer, and incident log.

## Observe Admin Approval

Default config uses file approval:

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

Expected behavior:

- `notify_admin` and `create_incident` are logged.
- Active defense is denied or skipped pending approval.

With approval:

```bash
echo APPROVE > /tmp/wazuh-llm-poc/APPROVE
wazuh-llm-poc --config config/poc.yaml --alerts samples/alerts.json --once
rm -f /tmp/wazuh-llm-poc/APPROVE
```

Expected behavior:

- Policy-allowed actions execute.
- If `dry_run: true`, `block_ip` emits the command that would have been run instead of changing the firewall.

## Observe Dry-run Block IP

To see a block command produced without changing the machine:

1. Use an alert with a public source IP.
2. Use an LLM verdict or policy settings that meet the confidence threshold.
3. Keep:

```yaml
runtime:
  dry_run: true
```

The response output will include something like:

```text
sudo iptables -A INPUT -s 203.0.113.10 -j DROP
```

## Observe Real Block IP in an Isolated Lab Only

Only after confirming safety:

```yaml
runtime:
  dry_run: false
```

Before doing this:

```bash
iptables -S
ip route
who
```

Make sure you are not blocking your own management IP and that you have console access.

## Dashboard Observation

In Wazuh Dashboard:

1. Go to Security events.
2. Filter by the agent name.
3. Filter by rule level >= 10.
4. Compare the alert timestamp and rule ID with the PoC stdout JSON.
5. Confirm that the PoC `alert.rule_id`, `agent.name`, and `timestamp` match the Dashboard event.
