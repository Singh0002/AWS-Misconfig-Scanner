"""Small helpers for reading AWS policy documents. Used by the S3 and IAM rules.

AWS lets most policy fields be either one value or a list, e.g. "Action": "*"
or "Action": ["s3:GetObject", "s3:PutObject"]. These helpers smooth that out
so the rules don't have to check both every time.
"""

import json


def load_policy(policy):
    """Returns the policy as a dict. Accepts a dict or the JSON string AWS returns."""
    if isinstance(policy, str):
        return json.loads(policy)
    return policy


def as_list(value):
    """"*" -> ["*"], None -> [], lists stay as they are."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(policy):
    """The policy's statements as a list, even if there is only one."""
    return as_list(load_policy(policy).get("Statement"))


def is_public_principal(principal):
    """True for "*", {"AWS": "*"} and {"AWS": ["*"]}, which all mean anyone."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in as_list(principal.get("AWS"))
    return False


def has_condition(statement):
    # an empty Condition block restricts nothing, so it counts as no condition
    return bool(statement.get("Condition"))
