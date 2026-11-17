__all__ = ["condition_restricts_principal"]
import re
from typing import Any, Dict

from pycfmodel.model.resources.properties.statement_condition import StatementCondition

# 12 digit AWS account ID, e.g. `123456789012`
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
# Organisation ID (`o-...`) or organisation path (`o-.../ou-.../...`)
ORGANISATION_ID_PATTERN = re.compile(r"^o-[a-z0-9]{10,32}(/ou-[a-z0-9-]{4,32}(/[a-z0-9.-]+)*)?$")
# Fully qualified ARN without wildcard characters
ARN_PATTERN = re.compile(r"^arn:aws[a-z-]*:([*\w]+):([a-z0-9-]*):(\d{12})?:[^*?]+$")

# Only positive, mandatory operators can prove the restriction. Negated operators (`*NotEquals`,
# `*NotLike`), `*IfExists` variants, `Null` and set quantifiers (`ForAllValues:`/`ForAnyValue:`)
# either do not guarantee the key is present or can be satisfied by an unrestricted principal.
PROVEN_OPERATORS = {
    "StringEquals": ("aws:PrincipalAccount", "aws:SourceAccount", "aws:PrincipalOrgID", "aws:PrincipalOrgPaths"),
    "StringEqualsIgnoreCase": (
        "aws:PrincipalAccount",
        "aws:SourceAccount",
        "aws:PrincipalOrgID",
        "aws:PrincipalOrgPaths",
    ),
    "ArnEquals": ("aws:PrincipalArn", "aws:SourceArn"),
    "ArnLike": ("aws:PrincipalArn", "aws:SourceArn"),
}

UNRESOLVED_VALUE_PREFIXES = ("GETATT", "UNDEFINED_")


def condition_restricts_principal(condition: StatementCondition) -> bool:
    """
    Returns `True` only when the condition can be statically proven to narrow a wildcard principal
    down to explicit AWS accounts, organisations or principal ARNs.

    Anything that cannot be proven (unsupported operators, negation, existence checks, set quantifiers,
    wildcard values, CloudFormation intrinsic functions, conditions on unrelated parameters) returns
    `False` so the wildcard principal keeps being reported as a risk.
    """
    operators = condition.model_dump(exclude_none=True)
    if not operators:
        return False
    for operator, key_constraints in operators.items():
        allowed_keys = PROVEN_OPERATORS.get(operator)
        if allowed_keys is None or not _operator_constrains_identity(allowed_keys, key_constraints):
            return False
    return True


def _operator_constrains_identity(allowed_keys: tuple, key_constraints: Dict[str, Any]) -> bool:
    if not key_constraints:
        return False
    for condition_key, raw_values in key_constraints.items():
        if condition_key not in allowed_keys or not _values_are_concrete(condition_key, raw_values):
            return False
    return True


def _values_are_concrete(condition_key: str, raw_values: Any) -> bool:
    # Values can be a single scalar or a list; lists are combined with a logical OR in AWS.
    values = raw_values if isinstance(raw_values, list) else [raw_values]
    if not values:
        return False
    return all(_value_is_concrete(condition_key, value) for value in values)


def _value_is_concrete(condition_key: str, value: Any) -> bool:
    # Unresolved CloudFormation intrinsic functions remain dicts, or become `GETATT`/`UNDEFINED_*`
    # placeholders after resolution; neither can prove who the principal will be.
    if isinstance(value, dict):
        return False
    if not isinstance(value, str) or value.startswith(UNRESOLVED_VALUE_PREFIXES):
        return False

    if condition_key in ("aws:PrincipalAccount", "aws:SourceAccount"):
        return bool(ACCOUNT_ID_PATTERN.match(value))
    if condition_key in ("aws:PrincipalOrgID", "aws:PrincipalOrgPaths"):
        return bool(ORGANISATION_ID_PATTERN.match(value))
    if condition_key in ("aws:PrincipalArn", "aws:SourceArn"):
        # `${...}` is the leftover of an unresolved `Fn::Sub`; the concrete ARN cannot be proven.
        return "${" not in value and "*" not in value and "?" not in value and bool(ARN_PATTERN.match(value))
    return False
