import pytest

from cfripper.rules import SQSQueuePolicyPublicRule
from tests.utils import get_cfmodel_from

FIXTURE = "rules/WildcardPrincipalConditionRule"


@pytest.fixture()
def narrowing_template():
    return get_cfmodel_from(f"{FIXTURE}/wildcard_principal_with_narrowing_conditions.json").resolve()


@pytest.fixture()
def non_narrowing_template():
    return get_cfmodel_from(f"{FIXTURE}/wildcard_principal_with_non_narrowing_conditions.json").resolve()


def test_narrowing_conditions_keep_the_queue_policy_private(narrowing_template):
    result = SQSQueuePolicyPublicRule(None).invoke(narrowing_template)

    assert result.valid
    assert result.failures == []


def test_non_narrowing_conditions_keep_the_queue_policy_failure(non_narrowing_template):
    result = SQSQueuePolicyPublicRule(None).invoke(non_narrowing_template)

    assert not result.valid
    assert {next(iter(failure.resource_ids)) for failure in result.failures} == {
        "ForAllValuesCondition",
        "ForAnyValueCondition",
    }
    assert all(
        failure.reason == "SQS Queue policy {} should not be public".format(next(iter(failure.resource_ids)))
        for failure in result.failures
    )
