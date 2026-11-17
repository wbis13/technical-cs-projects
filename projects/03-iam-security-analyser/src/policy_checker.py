# src/policy_checker.py
import boto3, json

def check_wildcard_policies() -> list:
    iam = boto3.client("iam")
    findings = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            version = iam.get_policy_version(
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]["Document"]
            for stmt in version.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    a_list = actions if isinstance(actions, list) else [actions]
                    r_list = resources if isinstance(resources, list) else [resources]
                    if "*" in a_list and "*" in r_list:
                        findings.append({
                            "policy": policy["PolicyName"],
                            "arn": policy["Arn"],
                            "severity": "CRITICAL",
                            "issue": "WILDCARD_POLICY",
                            "detail": "Policy grants Action:* on Resource:* — full admin access"
                        })
    return findings
