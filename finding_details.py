"""What the Results tab shows when someone picks a finding (E-4 S-7-3).

This file has no Streamlit code so it can be tested on its own. app.py calls
details(scan, finding) and draws what comes back.

The AI explanation can be in one of four states:
    available    - the AI explained it; show the text and the fix steps
    pending      - the AI hasn't been asked yet
    unavailable  - the AI was off or failed
    none         - there's no explanation record for this finding at all
Only "available" has text. The rule result is shown either way, because the
rules decide pass/fail, not the AI.
"""

import json

AI_MESSAGES = {
    "pending": "The AI explanation isn't ready yet.",
    "unavailable": "No AI explanation for this finding (AI was off or failed). "
                   "The rule result above is still correct.",
    "none": "No AI explanation for this finding.",
}


def find_check(scan, check_id):
    for check in scan["checks"]:
        if check["check_id"] == check_id:
            return check
    return None


SERVICE_FILTERS = ["S3", "IAM"]
SEVERITY_FILTERS = ["High", "Medium", "Low"]
FILTERS = SERVICE_FILTERS + SEVERITY_FILTERS


def filter_findings(scan, findings, shown):
    """The findings whose service AND severity are both picked in the filters (E-4 S-7-2).

    shown is the list of picked filter names, e.g. ["S3", "High", "Medium"].
    None (nothing set yet) shows everything.
    """
    if shown is None:
        return list(findings)
    kept = []
    for finding in findings:
        check = find_check(scan, finding["check_id"]) or {}
        if check.get("service") in shown and finding["severity"] in shown:
            kept.append(finding)
    return kept


def find_explanation(scan, finding_id):
    for explanation in scan.get("explanations", []):
        if explanation["finding_id"] == finding_id:
            return explanation
    return None


def label(scan, finding):
    """One line for the finding picker, e.g. "High | S3 | my-bucket | Versioning is not enabled"."""
    check = find_check(scan, finding["check_id"]) or {}
    return " | ".join([finding["severity"], check.get("service", "?"),
                       check.get("resource_id", "?"), finding["issue"]])


SEVERITY_COLORS = {"High": "red", "Medium": "orange", "Low": "blue"}


def title(scan, finding):
    """The heading of a finding on the Results tab, e.g.
    ":red-badge[High] **Versioning is not enabled** - `my-bucket` - S3"

    The resource goes in backticks so a name like my_user can't turn into italics.
    """
    check = find_check(scan, finding["check_id"]) or {}
    color = SEVERITY_COLORS.get(finding["severity"], "gray")
    return (":" + color + "-badge[" + finding["severity"] + "] **" + finding["issue"] + "** - `"
            + str(check.get("resource_id", "?")) + "` - " + str(check.get("service", "?")))


def describe(value):
    """Turns evidence values into plain words, e.g. {"group": "All Users"} -> "group All Users"."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            if item not in (None, "", []):
                parts.append(key.replace("_", " ") + " " + describe(item))
        return ", ".join(parts)
    if isinstance(value, list):
        return "; ".join(describe(item) for item in value)
    return str(value)


def evidence_lines(evidence_json):
    """The rule's evidence as readable lines, e.g. "Versioning status: Suspended"."""
    try:
        evidence = json.loads(evidence_json or "{}")
    except ValueError:
        return []
    lines = []
    for key, value in evidence.items():
        lines.append(key.replace("_", " ").capitalize() + ": " + describe(value))
    return lines


def explanation_view(explanation):
    """What to show for the AI part: its state, and the text and steps if there are any."""
    if explanation is None:
        state = "none"
    else:
        state = explanation["explanation_status"]

    if state == "available":
        text = explanation.get("risk_explanation") or ""
        try:
            steps = json.loads(explanation.get("recommended_steps_json") or "[]")
        except ValueError:
            steps = []
        if not isinstance(steps, list):
            steps = []
        if text or steps:
            return {"state": "available", "text": text, "steps": [str(s) for s in steps], "message": None}
        # marked available but empty, so treat it like the AI failed
        state = "unavailable"

    return {"state": state, "text": None, "steps": [],
            "message": AI_MESSAGES.get(state, AI_MESSAGES["none"])}


def details(scan, finding):
    """Everything the details panel shows for one finding."""
    check = find_check(scan, finding["check_id"]) or {}
    return {
        "severity": finding["severity"],
        "issue": finding["issue"],
        "service": check.get("service", "?"),
        "resource": check.get("resource_id", "?"),
        "rule_id": check.get("rule_id", "?"),
        "evidence": evidence_lines(check.get("evidence_json")),
        "explanation": explanation_view(find_explanation(scan, finding["finding_id"])),
    }
