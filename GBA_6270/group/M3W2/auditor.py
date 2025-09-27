#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auditor.py - VM Network Security Auditing Tool
Runs on VM1 (control-station).
- Loads device inventory
- Connects via SSH (paramiko)
- Extracts sshd_config, passwd, ufw rules
- Compares with baselines (YAML)
- Identifies violations (critical/warning)
- Calculates security score (100 base, -15 critical, -5 warning)
- Saves JSON report in reports/
"""

import os
import sys
import json
import yaml
import paramiko
from datetime import datetime
from typing import Dict, List, Any, Tuple

BASE_DIR = os.path.expanduser("~/network-auditor")
INVENTORY_PATH = os.path.join(BASE_DIR, "device_inventory.yaml")
BASELINES_DIR = os.path.join(BASE_DIR, "baselines")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Fallback creds (per your note)
FALLBACK_USER = "audituser"
FALLBACK_PASS = "AuditPass123"

# ---------- Helpers ----------

def load_yaml(path: str) -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing required file: {path}")
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}

def ensure_dirs():
    os.makedirs(REPORTS_DIR, exist_ok=True)

def load_inventory(path: str = INVENTORY_PATH) -> List[Dict[str, Any]]:
    data = load_yaml(path)
    devices = data.get("devices", [])
    if not devices:
        raise ValueError("No devices found in device_inventory.yaml")
    return devices

def ssh_connect(host: str, username: str, password: str, timeout: int = 10) -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=username, password=password, timeout=timeout, allow_agent=False, look_for_keys=False)
    return c

def run_cmd(client: paramiko.SSHClient, cmd: str) -> Tuple[str, str, int]:
    """Return (stdout, stderr, exit_status). Uses non-interactive sudo (-n)."""
    if cmd.strip().startswith("sudo "):
        cmd = cmd.replace("sudo ", "sudo -n ", 1)
    stdin, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    return out, err, rc

# ---------- Extraction ----------

def parse_sshd_config(text: str) -> Dict[str, str]:
    """Very simple key/value parser for sshd_config (last occurrence wins)."""
    result: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, val = parts[0].strip(), parts[1].strip()
            # normalize key casing like PermitRootLogin, MaxAuthTries, etc.
            result[key] = val
    return result

def parse_passwd(text: str) -> List[str]:
    """Return list of usernames from /etc/passwd."""
    users = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) >= 1:
            users.append(fields[0])
    return users

def parse_ufw_status_numbered(text: str) -> List[Dict[str, Any]]:
    """
    Parse 'ufw status numbered' sample lines like:
    [ 1] 22/tcp ALLOW IN Anywhere
    Return list of dicts: {port:int, protocol:str, action:'ALLOW'/'DENY'/'REJECT', direction:'IN'/'OUT'?, raw:str}
    """
    rules = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith('['):
            continue
        # remove leading [ n]
        try:
            after = line.split(']', 1)[1].strip()
        except Exception:
            continue
        # Common format: "22/tcp ALLOW IN Anywhere"
        parts = after.split()
        if len(parts) < 3:
            continue
        port_proto = parts[0]           # e.g., 22/tcp or 443/tcp
        action = parts[1].upper()       # ALLOW / DENY / REJECT
        direction = parts[2].upper()    # IN / OUT (usually IN)
        port = None
        proto = None
        if '/' in port_proto:
            p, pr = port_proto.split('/', 1)
            try:
                port = int(p)
            except ValueError:
                # Sometimes "Anywhere" or "Anywhere (v6)" appears; skip if no port
                continue
            proto = pr.lower()
        rules.append({
            "port": port,
            "protocol": proto,
            "action": action,
            "direction": direction,
            "raw": line
        })
    return rules

def extract_configs(client: paramiko.SSHClient) -> Dict[str, Any]:
    # sshd_config
    sshd_out, _, _ = run_cmd(client, "cat /etc/ssh/sshd_config")
    sshd = parse_sshd_config(sshd_out)

    # passwd
    passwd_out, _, _ = run_cmd(client, "cat /etc/passwd")
    users = parse_passwd(passwd_out)

    # ufw (enable may not be required to read status; use sudo just in case)
    ufw_out, ufw_err, ufw_rc = run_cmd(client, "sudo ufw status numbered")
    # If ufw not installed / inactive, handle gracefully
    ufw_rules = parse_ufw_status_numbered(ufw_out) if ufw_rc == 0 else []

    return {
        "sshd_config_raw": sshd_out,
        "sshd_config": sshd,
        "passwd_raw": passwd_out,
        "users": users,
        "ufw_status_raw": ufw_out if ufw_rc == 0 else ufw_err,
        "ufw_rules": ufw_rules
    }

# ---------- Baseline Comparison ----------

def load_baselines() -> Dict[str, Any]:
    ssh_baseline = load_yaml(os.path.join(BASELINES_DIR, "ssh_baseline.yaml"))
    fw_baseline  = load_yaml(os.path.join(BASELINES_DIR, "firewall_baseline.yaml"))
    users_base   = load_yaml(os.path.join(BASELINES_DIR, "users_baseline.yaml"))
    return {
        "ssh": ssh_baseline,
        "fw": fw_baseline,
        "users": users_base,
    }

def compare_ssh(sshd: Dict[str, str], ssh_baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
    violations = []
    rules = ssh_baseline.get("compliance_rules", [])
    for r in rules:
        param = r.get("parameter")
        expected = str(r.get("expected")).strip()
        severity = r.get("severity", "warning").lower()
        actual = sshd.get(param)
        # Special handling: MaxAuthTries expected "3" means actual must be <= 3
        is_violation = False
        if param and actual is not None:
            if param.lower() == "maxauthtries":
                try:
                    is_violation = int(actual) > int(expected)
                except Exception:
                    is_violation = True
            else:
                is_violation = str(actual).strip().lower() != expected.lower()
        else:
            # missing parameter is also a violation (treat as not set)
            is_violation = True
            actual = "<not set>"

        if is_violation:
            violations.append({
                "category": "ssh",
                "rule": r.get("rule", f"{param} must be {expected}"),
                "parameter": param,
                "expected": expected,
                "actual": actual,
                "severity": severity,
                "recommendation": f"Set {param} to {expected} in /etc/ssh/sshd_config and restart sshd (sudo systemctl restart ssh)."
            })
    return violations

def compare_users(actual_users: List[str], users_baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
    violations = []

    # Required users must exist
    for req in users_baseline.get("required_users", []):
        u = req.get("username")
        sev = req.get("severity", "critical").lower()
        if u and u not in actual_users:
            violations.append({
                "category": "users",
                "rule": f"Required user '{u}' must exist",
                "parameter": "user_presence",
                "expected": f"user '{u}' present",
                "actual": "absent",
                "severity": sev,
                "recommendation": f"Create the required user: sudo useradd -m {u}"
            })

    # Prohibited users must not exist
    for bad in users_baseline.get("prohibited_users", []):
        u = bad.get("username")
        sev = bad.get("severity", "warning").lower()
        if u and u in actual_users:
            violations.append({
                "category": "users",
                "rule": f"Prohibited user '{u}' must not exist",
                "parameter": "user_absence",
                "expected": f"user '{u}' absent",
                "actual": "present",
                "severity": sev,
                "recommendation": f"Remove the prohibited user: sudo userdel -r {u}"
            })

    # Password policy in baseline exists, but requirement only asked to extract /etc/passwd,
    # so we won't evaluate password aging here.
    return violations

def firewall_rule_present(rules: List[Dict[str, Any]], port: int, proto: str, expect_action: str) -> bool:
    for r in rules:
        if r.get("port") == port and (r.get("protocol") == proto.lower()) and r.get("action") == expect_action.upper():
            return True
    return False

def compare_firewall(ufw_rules: List[Dict[str, Any]], fw_baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
    violations = []

    # Required rules must be present with ACCEPT/ALLOW
    for req in fw_baseline.get("required_rules", []):
        port = req.get("port")
        proto = (req.get("protocol") or "").lower()
        action = req.get("action", "ACCEPT").upper()
        sev = req.get("severity", "warning").lower()
        desc = req.get("description", f"Port {port}/{proto} must be {action}")
        # Map baseline "ACCEPT" to UFW "ALLOW"
        expect_action = "ALLOW" if action == "ACCEPT" else action
        if not firewall_rule_present(ufw_rules, port, proto, expect_action):
            violations.append({
                "category": "firewall",
                "rule": desc,
                "parameter": f"ufw {port}/{proto}",
                "expected": f"{expect_action}",
                "actual": "missing",
                "severity": sev,
                "recommendation": f"sudo ufw allow {port}/{proto}"
            })

    # Blocked rules must be blocked/absent; if ALLOW present, it's a violation
    for blk in fw_baseline.get("blocked_rules", []):
        port = blk.get("port")
        proto = (blk.get("protocol") or "").lower()
        action = blk.get("action", "DROP").upper()
        sev = blk.get("severity", "warning").lower()
        desc = blk.get("description", f"Port {port}/{proto} should be {action}")
        # If it's ALLOW, it's a violation
        if firewall_rule_present(ufw_rules, port, proto, "ALLOW"):
            violations.append({
                "category": "firewall",
                "rule": desc,
                "parameter": f"ufw {port}/{proto}",
                "expected": f"not ALLOW (should be {action})",
                "actual": "ALLOW",
                "severity": sev,
                "recommendation": f"sudo ufw delete allow {port}/{proto} && sudo ufw deny {port}/{proto}"
            })

    # Default policy check omitted (not extracted in requirement). Could add: `sudo ufw status verbose`.
    return violations

def score_from_violations(violations: List[Dict[str, Any]]) -> int:
    score = 100
    for v in violations:
        sev = v.get("severity", "warning").lower()
        if sev == "critical":
            score -= 15
        else:
            score -= 5
    return max(score, 0)

# ---------- Reporting ----------

def save_json_report(device: Dict[str, Any], facts: Dict[str, Any], violations: List[Dict[str, Any]]):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    hostname = device.get("hostname", device.get("ip", "unknown")).replace(" ", "_")
    fpath = os.path.join(REPORTS_DIR, f"report_{hostname}_{ts}.json")
    report = {
        "generated_at_utc": ts,
        "device": {
            "hostname": device.get("hostname"),
            "ip": device.get("ip"),
            "description": device.get("description"),
        },
        "extracted": {
            "users_count": len(facts.get("users", [])),
            "ufw_rules_count": len(facts.get("ufw_rules", [])),
        },
        "violations_grouped": {
            "critical": [v for v in violations if v.get("severity") == "critical"],
            "warning":  [v for v in violations if v.get("severity") == "warning"],
        },
        "security_score": score_from_violations(violations),
        "violations": violations,  # full list
    }
    with open(fpath, "w") as f:
        json.dump(report, f, indent=2)
    return fpath

def print_console_summary(device: Dict[str, Any], violations: List[Dict[str, Any]]):
    crit = [v for v in violations if v.get("severity") == "critical"]
    warn = [v for v in violations if v.get("severity") == "warning"]
    score = score_from_violations(violations)
    print(f"\n=== Audit Summary: {device.get('hostname')} ({device.get('ip')}) ===")
    print(f"Security Score: {score}/100")
    print(f"Critical: {len(crit)} | Warning: {len(warn)}")
    if violations:
        print("Violations:")
        for v in violations:
            print(f" - [{v['severity'].upper()}] {v['category']}: {v['rule']}")
            print(f"    Expected: {v['expected']} | Actual: {v['actual']}")
            print(f"    Remediation: {v['recommendation']}")

# ---------- Main ----------

def audit_device(device: Dict[str, Any], baselines: Dict[str, Any]):
    ip = device.get("ip")
    user = device.get("username") or FALLBACK_USER
    pwd = device.get("password") or FALLBACK_PASS

    client = None
    try:
        print(f"\n[+] Connecting to {device.get('hostname')} ({ip}) as {user} ...")
        client = ssh_connect(ip, user, pwd)
        # Sanity test
        out, _, _ = run_cmd(client, "hostname && uptime")
        print(out.strip())

        # Extract
        facts = extract_configs(client)

        # Compare against baselines
        v_ssh = compare_ssh(facts.get("sshd_config", {}), baselines["ssh"])
        v_users = compare_users(facts.get("users", []), baselines["users"])
        v_fw = compare_firewall(facts.get("ufw_rules", []), baselines["fw"])
        violations = v_ssh + v_users + v_fw

        # Report
        ensure_dirs()
        report_path = save_json_report(device, facts, violations)
        print_console_summary(device, violations)
        print(f"Saved JSON report: {report_path}")

    except Exception as e:
        print(f"[!] Audit failed for {ip}: {e}")
    finally:
        if client:
            client.close()

def main():
    try:
        ensure_dirs()
        devices = load_inventory()
        baselines = load_baselines()
    except Exception as e:
        print(f"[!] Setup error: {e}")
        sys.exit(1)

    for d in devices:
        audit_device(d, baselines)

if __name__ == "__main__":
    main()
