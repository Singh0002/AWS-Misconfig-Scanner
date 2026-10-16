"""The result format every module uses (collectors, rules, AI, storage).

Results are just dictionaries. Each one has the same keys as its table in
storage/db.py so we can save them without converting anything.

A full scan looks like:

    {
        "metadata": {...},      # the scans table row
        "checks": [...],        # every resource + rule we checked
        "findings": [...],      # only the checks that failed
        "explanations": [...],  # AI output, one per finding
        "errors": [...],        # what went wrong (no secrets in here!)
    }

Please use the make_ functions instead of writing the dicts yourself.
"""

import json
import uuid
from datetime import datetime, timezone

SERVICES = ["S3", "IAM"]
CHECK_STATUSES = ["pass", "fail", "incomplete"]
SEVERITIES = ["High", "Medium", "Low"]
EXPLANATION_STATUSES = ["pending", "available", "unavailable"]
ERROR_STAGES = ["collection", "detection", "AI", "storage", "reporting"]


def new_scan(selected_services, account_id=None):
    """Returns a new empty scan with its own ID and the current UTC time."""
    if len(selected_services) == 0:
        raise ValueError("Select at least one service.")
    for service in selected_services:
        check_allowed("service", service, SERVICES)

    metadata = {
        "scan_id": uuid.uuid4().hex,
        "account_id": account_id,
        "scan_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "selected_services": json.dumps(selected_services),
        "scan_status": "running",
        "coverage_status": "complete",
    }
    return {
        "metadata": metadata,
        "checks": [],
        "findings": [],
        "explanations": [],
        "errors": [],
    }


def make_check(scan_id, service, resource_id, rule_id, status, evidence=None, reason=None):
    """One resource checked against one rule. evidence should be a dict."""
    check_allowed("service", service, SERVICES)
    check_allowed("status", status, CHECK_STATUSES)
    if evidence is None:
        evidence = {}

    # building the ID from these means the same check always gets the same ID
    check_id = scan_id + "/" + service + "/" + rule_id + "/" + resource_id

    return {
        "check_id": check_id,
        "scan_id": scan_id,
        "service": service,
        "resource_id": resource_id,
        "rule_id": rule_id,
        "status": status,
        "evidence_json": json.dumps(evidence),
        "reason": reason,
    }


def make_finding(check, issue, severity):
    """Makes the finding for a failed check."""
    if check["status"] != "fail":
        raise ValueError("Only failed checks can have a finding.")
    check_allowed("severity", severity, SEVERITIES)

    return {
        "finding_id": check["check_id"] + "/finding",
        "check_id": check["check_id"],
        "issue": issue,
        "severity": severity,
    }


def make_explanation(finding_id, status, risk_explanation=None, recommended_steps=None):
    """What the AI said about one finding. recommended_steps is a list of strings."""
    check_allowed("explanation status", status, EXPLANATION_STATUSES)

    steps_json = None
    if recommended_steps:
        steps_json = json.dumps(recommended_steps)

    return {
        "finding_id": finding_id,
        "explanation_status": status,
        "risk_explanation": risk_explanation,
        "recommended_steps_json": steps_json,
    }


def make_error(scan_id, stage, operation, message, resource_id=None):
    """An error we show the user. Don't put keys or secrets in the message."""
    check_allowed("stage", stage, ERROR_STAGES)
    return {
        "scan_id": scan_id,
        "stage": stage,
        "operation": operation,
        "resource_id": resource_id,
        "message": message,
    }


def check_allowed(name, value, allowed):
    if value not in allowed:
        raise ValueError(f"Invalid {name}: {value}. Must be one of {allowed}.")
