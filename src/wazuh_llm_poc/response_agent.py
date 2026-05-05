from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .models import ResponseResult


def _append_jsonl(path: str | Path, record: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def request_approval(actions: List[Dict[str, Any]], approval_mode: str, approval_file: str | None = None) -> bool:
    """Human approval gate. Default safe behavior: no approval means no active execution."""
    if not actions:
        return False
    if approval_mode == "auto_approve_for_lab_only":
        return True
    if approval_mode == "file":
        if not approval_file:
            return False
        p = Path(approval_file)
        return p.exists() and p.read_text(encoding="utf-8").strip().upper() == "APPROVE"
    if approval_mode == "interactive":
        print("\nPolicy-allowed actions pending admin approval:")
        for i, action in enumerate(actions, 1):
            print(f"{i}. {action}")
        ans = input("Execute these actions? Type APPROVE to continue: ").strip()
        return ans == "APPROVE"
    return False


def execute_actions(actions: List[Dict[str, Any]], runtime: Dict[str, Any]) -> ResponseResult:
    result = ResponseResult()
    dry_run = bool(runtime.get("dry_run", True))
    incident_log = runtime.get("incident_log", "./incidents.jsonl")

    for action in actions:
        typ = action.get("type")
        target = str(action.get("target", ""))
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "dry_run": dry_run,
            "action": action,
        }

        if typ in {"notify_admin", "create_incident"}:
            _append_jsonl(incident_log, record)
            result.executed.append({**action, "status": "logged"})
        elif typ == "block_ip":
            cmd_template = runtime.get("block_ip_command", "sudo iptables -A INPUT -s {target} -j DROP")
            cmd = cmd_template.format(target=target)
            record["command"] = cmd
            _append_jsonl(incident_log, record)
            if dry_run:
                result.executed.append({**action, "status": "dry_run", "command": cmd})
            else:
                completed = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=20)
                result.executed.append({**action, "status": "executed", "returncode": completed.returncode, "stderr": completed.stderr})
        elif typ in {"quarantine_file", "kill_process", "disable_account"}:
            record["note"] = "PoC logs these high-impact actions; production should bind to audited EDR/SOAR APIs."
            _append_jsonl(incident_log, record)
            result.skipped.append({**action, "status": "not_implemented_high_impact_poc"})
        else:
            result.skipped.append({**action, "status": "unknown_action"})
    return result
