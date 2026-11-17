import pytest

from cfripper.model.result import Failure
from cfripper.rules import KMSKeyWildcardPrincipalRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def kms_key_with_wildcard_policy():
    return get_cfmodel_from("rules/KMSKeyWildcardPrincipalRule/kms_key_with_wildcard_resource.json").resolve()


@pytest.fixture()
def kms_key_without_policy():
    return get_cfmodel_from("rules/KMSKeyWildcardPrincipalRule/kms_key_without_policy.yml").resolve()


@pytest.fixture()
def kms_key_with_wildcard_and_conditions():
    return get_cfmodel_from("rules/KMSKeyWildcardPrincipalRule/kms_key_with_wildcard_and_conditions.json").resolve()


def test_kms_key_with_wildcard_resource_not_allowed_is_flagged(kms_key_with_wildcard_policy):
    rule = KMSKeyWildcardPrincipalRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(kms_key_with_wildcard_policy)

    assert result.valid is False
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity="RESOURCE",
                reason="KMS Key policy myKey should not allow wildcard principals",
                risk_value="MEDIUM",
                rule="KMSKeyWildcardPrincipalRule",
                rule_mode="BLOCKING",
                actions=None,
                resource_ids={"myKey"},
                resource_types=None,
            )
        ],
    )


def test_kms_key_without_policy_is_not_flagged(kms_key_without_policy):
    rule = KMSKeyWildcardPrincipalRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(kms_key_without_policy)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_kms_key_wildcard_principal_narrowed_by_condition_is_not_flagged(kms_key_with_wildcard_and_conditions):
    rule = KMSKeyWildcardPrincipalRule(None)
    rule._config.stack_name = "stack3"
    rule.all_cf_actions = set()
    result = rule.invoke(kms_key_with_wildcard_and_conditions)

    assert not result.valid
    assert {next(iter(failure.resource_ids)) for failure in result.failures} == {
        "OpenWithForAllValuesCondition",
        "OpenWithUnrelatedCondition",
    }
    assert all(
        failure.reason
        == "KMS Key policy {} should not allow wildcard principals".format(next(iter(failure.resource_ids)))
        for failure in result.failures
    )
