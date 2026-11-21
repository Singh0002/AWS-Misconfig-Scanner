"""Helpers for reading AWS policy docs"""

import json


def load_policy(policy):
    """Returns the policy as a dict. Accepts a dict or the JSON string AWS returns"""
    if isinstance(policy, str):
        return json.loads(policy)
    return policy


def as_list(value):
    """lists stay as they are"""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(policy):
    """The policy's statements as a list, even if there is only one"""
    return as_list(load_policy(policy).get("Statement"))


def is_public_principal(principal):
    """True for "*", {"AWS": "*"} and {"AWS": ["*"]}, which all mean anyone"""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in as_list(principal.get("AWS"))
    return False


def has_condition(statement):
    # an empty Condition block restricts nothing it counts as no condition
    return bool(statement.get("Condition"))
