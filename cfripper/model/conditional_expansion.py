"""
Conservative expansion of CloudFormation conditional logic.

CloudFormation templates can wrap policy content (``Principal``, ``Resource``,
whole statements, ...) in intrinsic functions such as ``Fn::If``, ``Fn::Sub``
and ``Fn::Join``. The static rules only understand plain strings, so an opaque
function dict used to be silently ignored, which could turn an insecure branch
into a false negative.

The expansion in this module never tries to guess which branch CloudFormation
will actually take. Every ``Fn::If`` is split into both of its possibilities,
producing one concrete template variant per branch combination. Values that
cannot be proven statically are replaced with :data:`UNKNOWN_VALUE`, a wildcard
string. Rules therefore evaluate a concrete value on every branch and treat
unprovable values conservatively instead of seeing the function's "string shell".
"""

import copy
import logging
from itertools import product
from typing import Any, Dict, Iterator, List, Tuple

import pycfmodel
from pycfmodel.model.cf_model import CFModel

logger = logging.getLogger(__file__)

#: Sentinel rendered in place of any intrinsic value that cannot be proven
#: statically (``Ref``, ``Fn::GetAtt``, ``Fn::ImportValue``, ...). It is a bare
#: wildcard so wildcard-sensitive rules keep flagging the statement instead of
#: silently trusting an unknown value.
UNKNOWN_VALUE = "*"

#: Maximum number of branch variants produced for one template. Each
#: condition doubles the variant count (``2 ** conditions``), so the cap keeps
#: pathological templates from exhausting memory or scanning time. When the cap
#: is exceeded every conditional value is treated as unknown instead.
MAX_BRANCH_VARIANTS = 64

#: Intrinsic functions which collapse a list into a single string. When any of
#: their inputs is unknown the whole result is unknown.
_STRING_JOINING_FUNCTIONS = {"Fn::Join", "Fn::Sub", "Fn::Select", "Fn::Base64"}

#: Policy document statement fields whose value must be conservatively treated
#: as an unknown wildcard when an intrinsic function survives expansion.
_UNKNOWN_POLICY_FIELDS = ("Action", "NotAction", "Resource", "NotResource")
_UNKNOWN_PRINCIPAL_FIELDS = ("Principal", "NotPrincipal")

#: Intrinsic functions whose result cannot be known without the deployment
#: context. ``Fn::If`` is handled separately by :func:`_resolve_fn_if`.
_UNRESOLVABLE_FUNCTIONS = {
    "Ref",
    "Fn::GetAtt",
    "Fn::GetAZs",
    "Fn::ImportValue",
    "Fn::FindInMap",
    "Fn::Split",
}


def expand_conditional_template(template: Dict[str, Any]) -> List[Tuple[Tuple[str, ...], Dict[str, Any]]]:
    """
    Expand a raw CloudFormation template into all ``Fn::If`` branch variants.

    Each returned item is a ``(branch_path, expanded_template)`` pair. The
    branch path is a tuple of locatable descriptors such as
    ``"IsProd[true]"`` describing every conditional choice taken in that
    variant. A template without any ``Fn::If`` yields a single variant with an
    empty branch path and a deep copy of the original document.

    The input template is never mutated.
    """
    condition_names = _collect_condition_names(template)
    if not condition_names:
        return [((), copy.deepcopy(template))]

    if 2 ** len(condition_names) > MAX_BRANCH_VARIANTS:
        logger.warning(
            "Template defines %s conditional branches (more than the %s variant cap); "
            "treating every Fn::If value as unknown to stay conservative.",
            2 ** len(condition_names),
            MAX_BRANCH_VARIANTS,
        )
        return [
            (
                ("unresolved-conditions",),
                normalise_unknown_policy_values(_blanket_unknown(template)),
            )
        ]

    variants: List[Tuple[Tuple[str, ...], Dict[str, Any]]] = []
    for truth_assignment in product((True, False), repeat=len(condition_names)):
        assignments = dict(zip(condition_names, truth_assignment))
        branch_path = tuple(
            f"{condition_name}[{'true' if assignments[condition_name] else 'false'}]"
            for condition_name in condition_names
        )
        expanded_template = _expand_node(template, assignments)
        variants.append((branch_path, expanded_template))
    return variants


def expand_conditional_cfmodel(cfmodel: CFModel) -> List[Tuple[Tuple[str, ...], CFModel]]:
    """
    Expand a parsed :class:`CFModel` into branch-specific models.

    The model is serialised back to its raw dictionary representation before
    expansion, so the same single code path handles every nesting of
    ``Fn::If``, ``Fn::Sub`` and ``Fn::Join``.
    """
    raw_template = cfmodel.model_dump()
    variants = expand_conditional_template(raw_template)
    return [
        (
            branch_path,
            pycfmodel.parse(
                expanded_template if not branch_path else normalise_unknown_policy_values(expanded_template)
            ),
        )
        for branch_path, expanded_template in variants
    ]


def normalise_unknown_policy_values(template: Dict[str, Any]) -> Dict[str, Any]:
    """
    Replace any residual intrinsic-function dict used as an IAM policy value.

    Expansion resolves every supported intrinsic to a concrete value or to
    :data:`UNKNOWN_VALUE`. This function is the defensive second layer: if an
    unsupported function still occupies an ``Action``, ``Resource`` or
    ``Principal`` slot in a policy statement, it is replaced by
    :data:`UNKNOWN_VALUE` so rules cannot read the function's string shell and
    conclude the statement is safe. Only conditional variants are normalised;
    plain static templates keep their historical representation.
    """
    normalised = copy.deepcopy(template)
    resources = normalised.get("Resources")
    if not isinstance(resources, dict):
        return normalised

    for resource in resources.values():
        if not isinstance(resource, dict):
            continue
        for policy_document in _iter_policy_documents(resource):
            _normalise_policy_document(policy_document)
    return normalised


def _iter_policy_documents(resource: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    properties = resource.get("Properties")
    if not isinstance(properties, dict):
        return

    direct_documents = (
        "AssumeRolePolicyDocument",
        "PolicyDocument",
        "KeyPolicy",
        "AccessPolicies",
    )
    for field in direct_documents:
        document = properties.get(field)
        if isinstance(document, dict):
            yield document

    policies = properties.get("Policies")
    if isinstance(policies, list):
        for policy in policies:
            if isinstance(policy, dict) and isinstance(policy.get("PolicyDocument"), dict):
                yield policy["PolicyDocument"]


def _normalise_policy_document(policy_document: Dict[str, Any]) -> None:
    statements = policy_document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        for field in _UNKNOWN_POLICY_FIELDS:
            statement[field] = _normalise_policy_field(statement.get(field))
        for field in _UNKNOWN_PRINCIPAL_FIELDS:
            statement[field] = _normalise_principal_field(statement.get(field))


def _normalise_policy_field(value: Any) -> Any:
    if isinstance(value, dict):
        return UNKNOWN_VALUE if _is_unresolved_function(value) else value
    if isinstance(value, list):
        return [UNKNOWN_VALUE if isinstance(item, dict) and _is_unresolved_function(item) else item for item in value]
    return value


def _normalise_principal_field(value: Any) -> Any:
    if isinstance(value, dict):
        if _is_unresolved_function(value):
            return UNKNOWN_VALUE
        return {key: _normalise_policy_field(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_normalise_principal_field(item) for item in value]
    return value


def _is_unresolved_function(node: Dict[str, Any]) -> bool:
    """
    Whether a surviving dict is an intrinsic whose value stays unprovable.

    After expansion, deterministic functions such as a parameter-free
    ``Fn::Sub`` remain as plain function dicts but still represent one concrete
    string, so they must not be turned into wildcards. Only functions that
    depend on deployment-time values (or a residual ``Fn::If``) are unknown.
    """
    if "Fn::If" in node:
        return True
    if len(node) != 1:
        return False
    function_name = next(iter(node))
    return (
        function_name in _UNRESOLVABLE_FUNCTIONS
        or function_name in _STRING_JOINING_FUNCTIONS
        and _contains_unknown(node[function_name])
    )


def _expand_node(node: Any, assignments: Dict[str, bool]) -> Any:
    """Expand a node under one fixed truth assignment for every condition."""
    if isinstance(node, dict):
        return _expand_dict(node, assignments)
    elif isinstance(node, list):
        return [_expand_node(item, assignments) for item in node]
    else:
        return node


def _expand_dict(node: Dict[str, Any], assignments: Dict[str, bool]) -> Any:
    if "Fn::If" in node:
        return _resolve_fn_if(node["Fn::If"], assignments)

    function_name = next(iter(node), None)
    if function_name in _UNRESOLVABLE_FUNCTIONS:
        return UNKNOWN_VALUE

    expanded_dict = {key: _expand_node(value, assignments) for key, value in node.items()}

    if function_name in _STRING_JOINING_FUNCTIONS and _contains_unknown(expanded_dict):
        return UNKNOWN_VALUE
    return expanded_dict


def _resolve_fn_if(if_body: Any, assignments: Dict[str, bool]) -> Any:
    # Malformed Fn::If (not a 3-element list) cannot be interpreted safely:
    # treat the whole expression as unknown rather than dropping it.
    if not isinstance(if_body, list) or len(if_body) != 3:
        return UNKNOWN_VALUE

    condition_name, true_section, false_section = if_body
    if not isinstance(condition_name, str) or condition_name not in assignments:
        # An Fn::If referencing an unknown/malformed condition is unprovable:
        # both sections remain possible, so take the conservative option.
        return UNKNOWN_VALUE

    section = true_section if assignments[condition_name] else false_section
    return _expand_node(section, assignments)


def _contains_unknown(node: Any) -> bool:
    if node == UNKNOWN_VALUE:
        return True
    if isinstance(node, dict):
        return any(_contains_unknown(value) for value in node.values())
    if isinstance(node, list):
        return any(_contains_unknown(item) for item in node)
    return False


def _collect_condition_names(node: Any) -> List[str]:
    """Collect condition names referenced by ``Fn::If`` in first-seen order."""
    names: List[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if_body = value.get("Fn::If")
            if isinstance(if_body, list) and if_body and isinstance(if_body[0], str) and if_body[0] not in names:
                names.append(if_body[0])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(node)
    return names


def _blanket_unknown(node: Any) -> Any:
    """Replace every ``Fn::If`` expression with :data:`UNKNOWN_VALUE`."""
    if isinstance(node, dict):
        if "Fn::If" in node:
            return UNKNOWN_VALUE
        return {key: _blanket_unknown(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_blanket_unknown(item) for item in node]
    return node
