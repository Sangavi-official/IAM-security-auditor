"""
detector.py
"""

from __future__ import annotations
import json
from pathlib import Path

from cloudsplaining.shared.constants import PRIVILEGE_ESCALATION_METHODS

# Only the subset of Cloudsplaining's own method list that involves PassRole --
# these are the only methods where this particular resource-scoping blind
# spot is possible.
PASSROLE_METHODS = {
    name: actions
    for name, actions in PRIVILEGE_ESCALATION_METHODS.items()
    if "iam:passrole" in actions
}


def _as_list(value) -> list:
    """AWS lets Action/Resource/Statement be a single string OR a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def extract_granted_actions(policy_document: dict) -> set[str]:
    """Collect the set of actions granted by all 'Allow' statements, lowercased."""
    granted: set[str] = set()
    for statement in _as_list(policy_document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        for action in _as_list(statement.get("Action")):
            if isinstance(action, str):
                granted.add(action.lower())
    return granted


def _action_is_granted(required_action: str, granted_actions: set[str]) -> bool:
    if "*" in granted_actions:
        return True
    if required_action in granted_actions:
        return True
    service = required_action.split(":")[0]
    return f"{service}:*" in granted_actions


def _is_effectively_unrestricted(resource: str) -> bool:
    """
    True if the resource pattern's final path segment is a bare '*', meaning
    "any resource of this type in this scope" -- e.g.:
        "*"                                        -> True
        "arn:aws:iam::123456789012:role/*"          -> True  (any role name)
        "arn:aws:iam::123456789012:role/prod-*"     -> False (prefix-restricted)
        "arn:aws:iam::123456789012:role/DeployRole" -> False (one specific role)
    """
    if resource == "*":
        return True
    last_segment = resource.rsplit("/", 1)[-1]
    return last_segment == "*"


def find_unrestricted_passrole_resources(policy_document: dict) -> list[str]:
    """Return every Resource pattern on an Allow+iam:PassRole statement that
    is effectively unrestricted (matches any role in the account)."""
    found = []
    for statement in _as_list(policy_document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = {a.lower() for a in _as_list(statement.get("Action")) if isinstance(a, str)}
        if not ({"iam:passrole", "iam:*", "*"} & actions):
            continue
        for resource in _as_list(statement.get("Resource")):
            if isinstance(resource, str) and _is_effectively_unrestricted(resource):
                found.append(resource)
    return found


def find_passrole_blind_spots(policy_document: dict, cloudsplaining_flagged_methods: set) -> list:
    """
    The core finding of this project. Returns PassRole-based privilege
    escalation methods that:
      1. This policy's granted actions actually satisfy, AND
      2. Have an effectively-unrestricted PassRole resource pattern, AND
      3. Cloudsplaining's own allows_privilege_escalation did NOT already
         flag for this policy (i.e. a genuine blind spot, not a duplicate).
    """
    unrestricted_resources = find_unrestricted_passrole_resources(policy_document)
    if not unrestricted_resources:
        return []

    granted_actions = extract_granted_actions(policy_document)
    findings = []

    for method_name, required_actions in PASSROLE_METHODS.items():
        if method_name in cloudsplaining_flagged_methods:
            continue  # Cloudsplaining already caught this one -- not a blind spot

        other_required = [a for a in required_actions if a != "iam:passrole"]
        if all(_action_is_granted(a, granted_actions) for a in other_required):
            findings.append(
                {
                    "method": method_name,
                    "required_actions": required_actions,
                    "unrestricted_passrole_resource_patterns": unrestricted_resources,
                    "why_this_is_a_blind_spot": (
                        "iam:PassRole is scoped to a resource pattern that still "
                        "matches every role in the account. Cloudsplaining's check "
                        "requires a literal '*' Resource to flag this technique, so "
                        "it does not fire here -- even though the real-world blast "
                        "radius is identical to an unrestricted PassRole."
                    ),
                }
            )
    return findings


def load_policy(path) -> dict:
    with open(path) as f:
        return json.load(f)
