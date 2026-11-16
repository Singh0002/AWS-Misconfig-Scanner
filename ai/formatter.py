"""Checks AI replies and matches explanations to findings."""

import json

import results


def is_valid(item):
    """True if one item from the reply has everything we need."""
    if not isinstance(item, dict) or not isinstance(item.get("risk_explanation"), str):
        return False
    if item["risk_explanation"].strip() == "" or not isinstance(item.get("recommended_steps"), list):
        return False
    for step in item["recommended_steps"]:
        if not isinstance(step, str):
            return False
    return True


def parse_reply(text, finding_ids):
    try:
        items = json.loads(text)["explanations"]
    except (TypeError, ValueError, KeyError):
        # no reply, bad JSON, or the wrong shape
        items = []
    if not isinstance(items, list):
        items = []

    # finding_id means the item from the reply
    matched = {}
    for item in items:
        if is_valid(item) and item.get("finding_id") in finding_ids:
            matched[item["finding_id"]] = item

    explanations = []
    for finding_id in finding_ids:
        if finding_id not in matched:
            explanations.append(results.make_explanation(finding_id, "unavailable"))
            continue
        item = matched[finding_id]
        steps = []
        for step in item["recommended_steps"]:
            if step.strip():
                steps.append(step.strip())
        explanations.append(results.make_explanation(finding_id, "available", item["risk_explanation"].strip(), steps))
    return explanations
