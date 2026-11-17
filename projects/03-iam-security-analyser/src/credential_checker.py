# src/credential_checker.py
import boto3, csv, io, time
from datetime import datetime, timezone

def get_credential_report() -> list:
    iam = boto3.client("iam")
    iam.generate_credential_report()
    time.sleep(2)
    report = iam.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(report)))

def check_mfa_disabled(users: list) -> list:
    return [
        {"user": u["user"], "severity": "CRITICAL", "issue": "MFA_DISABLED",
         "detail": f"User {u['user']} has no MFA device enabled"}
        for u in users if u.get("mfa_active") == "false" and u["user"] != "<root_account>"
    ]

def check_stale_keys(users: list, max_days: int = 90) -> list:
    findings = []
    now = datetime.now(timezone.utc)
    for u in users:
        for key_num in ["1", "2"]:
            active = u.get(f"access_key_{key_num}_active")
            last_used = u.get(f"access_key_{key_num}_last_used_date")
            if active == "true" and last_used and last_used != "N/A":
                last_used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                days = (now - last_used_dt).days
                if days > max_days:
                    findings.append({
                        "user": u["user"], "severity": "HIGH", "issue": "STALE_ACCESS_KEY",
                        "detail": f"Access key {key_num} last used {days} days ago"
                    })
    return findings