"""Checks the JSON reply and matches it to the findings (E-4 S-9-2, S-9-3).

parse_reply(text, finding_ids) always gives back one explanation per
finding ID, in the same order. If the reply is missing, isn't valid JSON,
or leaves a finding out, that finding is marked unavailable. Anything for a
finding we didn't ask about is ignored.
"""

import json

import results


def is_valid(item):
    """True if one item from the reply has everything we need."""
    if not isinstance(item, dict):
        return False
    if not isinstance(item.get("finding_id"), str):
        return False
    text = item.get("risk_explanation")
    if not isinstance(text, str) or text.strip() == "":
        return False
    steps = item.get("recommended_steps")
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, str):
            return False
    return True


def parse_reply(text, finding_ids):
    # finding_id -> the item from the reply
    matched = {}
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("explanations"), list):
            for item in data["explanations"]:
                if is_valid(item) and item["finding_id"] in finding_ids:
                    matched[item["finding_id"]] = item

    explanations = []
    for finding_id in finding_ids:
        item = matched.get(finding_id)
        if item is None:
            explanations.append(results.make_explanation(finding_id, "unavailable"))
            continue

        steps = []
        for step in item["recommended_steps"]:
            if step.strip():
                steps.append(step.strip())
        explanations.append(results.make_explanation(
            finding_id, "available", item["risk_explanation"].strip(), steps))
    return explanations
