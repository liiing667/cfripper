import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import (
    FullWildcardPrincipalRule,
    GenericResourceFullWildcardPrincipalRule,
)
from tests.utils import compare_lists_of_failures, get_cfmodel_from

FIXTURE = "rules/WildcardPrincipalConditionRule"

NARROWING_RESOURCE_IDS = {
    "RestrictedBySourceAccount",
    "RestrictedByPrincipalAccount",
    "RestrictedByOrganisation",
    "RestrictedByOrganisationPath",
    "RestrictedBySourceArn",
    "RestrictedByPrincipalArnLike",
    "RestrictedByAccountAndOrganisation",
}

NON_NARROWING_RESOURCE_IDS = {
    "ForAllValuesCondition",
    "ForAnyValueCondition",
    "NegatedOperatorCondition",
    "IfExistsCondition",
    "NullCondition",
    "WildcardConditionValue",
    "MalformedAccountCondition",
    "UnrelatedParameterCondition",
    "IntrinsicConditionValue",
    "MixedNarrowingAndUnrelatedCondition",
}


@pytest.fixture()
def narrowing_template():
    return get_cfmodel_from(f"{FIXTURE}/wildcard_principal_with_narrowing_conditions.json").resolve()


@pytest.fixture()
def non_narrowing_template():
    return get_cfmodel_from(f"{FIXTURE}/wildcard_principal_with_non_narrowing_conditions.json").resolve()


@pytest.mark.parametrize("rule_cls", [FullWildcardPrincipalRule, GenericResourceFullWildcardPrincipalRule])
def test_narrowing_conditions_are_not_flagged(narrowing_template, rule_cls):
    result = rule_cls(None).invoke(narrowing_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


@pytest.mark.parametrize("rule_cls", [FullWildcardPrincipalRule, GenericResourceFullWildcardPrincipalRule])
def test_non_narrowing_conditions_keep_the_wildcard_principal_failure(non_narrowing_template, rule_cls):
    result = rule_cls(None).invoke(non_narrowing_template)

    assert not result.valid
    assert {next(iter(failure.resource_ids)) for failure in result.failures} == NON_NARROWING_RESOURCE_IDS
    assert all(failure.rule == rule_cls.__name__ for failure in result.failures)
    assert all(failure.granularity == RuleGranularity.RESOURCE for failure in result.failures)
    assert all(failure.risk_value == RuleRisk.HIGH for failure in result.failures)
    assert all(failure.rule_mode == RuleMode.BLOCKING for failure in result.failures)


def test_narrowing_failure_contains_statement_context(non_narrowing_template):
    result = FullWildcardPrincipalRule(None).invoke(non_narrowing_template)

    failure = next(
        failure for failure in result.failures if next(iter(failure.resource_ids)) == "ForAllValuesCondition"
    )
    assert isinstance(failure, Failure)
    assert failure.reason == (
        "ForAllValuesCondition should not allow full wildcard `*`, or wildcard in account ID like "
        "`arn:aws:iam::*:12345` at `*`"
    )
    assert failure.resource_types == {"AWS::SQS::QueuePolicy"}


def test_narrowing_fixture_covers_all_expected_resources(narrowing_template):
    assert set(narrowing_template.Resources.keys()) == NARROWING_RESOURCE_IDS


def test_non_narrowing_fixture_covers_all_expected_resources(non_narrowing_template):
    assert set(non_narrowing_template.Resources.keys()) == NON_NARROWING_RESOURCE_IDS
