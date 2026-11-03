"""Minimal SCP evaluator for unit tests.

Answers one question: does this deny-list SCP block the request?
It covers the operators used in this repository; anything else raises,
so a new operator never passes a test silently.
"""
import fnmatch
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "policies"


def load(relative_path):
    return json.loads((POLICIES / relative_path).read_text())


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _match(pattern, value):
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def _match_case(pattern, value):
    return fnmatch.fnmatchcase(value, pattern)


def _action_matches(statement, action):
    if "Action" in statement:
        return any(_match(p, action) for p in _as_list(statement["Action"]))
    return not any(_match(p, action) for p in _as_list(statement["NotAction"]))


def _resource_matches(statement, resource):
    return any(_match_case(p, resource) for p in _as_list(statement.get("Resource", "*")))


def _single(operator, expected, actual):
    """Evaluate one operator against a present key (actual is a list)."""
    if operator == "StringEquals":
        return any(a in expected for a in actual)
    if operator == "StringNotEquals":
        return all(a not in expected for a in actual)
    if operator == "StringLike":
        return any(_match_case(e, a) for e in expected for a in actual)
    if operator == "StringNotLike":
        return not any(_match_case(e, a) for e in expected for a in actual)
    if operator == "ArnLike":
        return any(_match_case(e, a) for e in expected for a in actual)
    if operator == "ArnNotLike":
        return not any(_match_case(e, a) for e in expected for a in actual)
    if operator == "Bool":
        return any(a.lower() == e.lower() for e in expected for a in actual)
    if operator == "NumericGreaterThan":
        return any(float(a) > float(e) for e in expected for a in actual)
    if operator == "NotIpAddress":
        nets = [ipaddress.ip_network(e) for e in expected]
        return all(not any(ipaddress.ip_address(a) in n for n in nets) for a in actual)
    raise NotImplementedError(operator)


NEGATED = {"StringNotEquals", "StringNotLike", "ArnNotLike", "NotIpAddress"}


def _condition_true(operator, key, expected, context):
    expected = [str(e) for e in _as_list(expected)]
    if operator == "Null":
        missing = key not in context
        return missing == (expected[0].lower() == "true")

    qualifier = None
    if ":" in operator and operator.split(":")[0] in ("ForAnyValue", "ForAllValues"):
        qualifier, operator = operator.split(":", 1)

    if_exists = operator.endswith("IfExists")
    base = operator[: -len("IfExists")] if if_exists else operator

    if key not in context:
        if if_exists:
            return True
        if qualifier == "ForAnyValue":
            return False
        # Negated operators match when the key is absent.
        return base in NEGATED

    actual = [str(v) for v in _as_list(context[key])]
    if qualifier == "ForAnyValue":
        return any(_single(base, expected, [a]) for a in actual)
    return _single(base, expected, actual)


def _conditions_true(statement, context):
    for operator, block in statement.get("Condition", {}).items():
        for key, expected in block.items():
            if not _condition_true(operator, key, expected, context):
                return False
    return True


def is_denied(policy, action, resource="*", context=None):
    """True if any Deny statement of the SCP matches the request."""
    context = context or {}
    for statement in policy["Statement"]:
        if statement["Effect"] != "Deny":
            continue
        if (_action_matches(statement, action)
                and _resource_matches(statement, resource)
                and _conditions_true(statement, context)):
            return True
    return False
