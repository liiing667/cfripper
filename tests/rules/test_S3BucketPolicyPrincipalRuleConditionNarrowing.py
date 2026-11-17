from pytest import fixture

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import S3BucketPolicyPrincipalRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@fixture()
def template_with_conditions():
    return get_cfmodel_from("rules/S3BucketPolicyPrincipalRule/bucket_policy_with_conditions.json").resolve()


def test_narrowing_condition_suppresses_non_allowed_principal(template_with_conditions):
    rule = S3BucketPolicyPrincipalRule(Config(aws_account_id="123456789012", aws_principals=["12345"]))
    result = rule.invoke(template_with_conditions)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="S3 Bucket OpenWithUnrelatedCondition policy has non-allowed principals 888888888888",
                risk_value=RuleRisk.HIGH,
                rule="S3BucketPolicyPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"OpenWithUnrelatedCondition"},
                resource_types={"AWS::S3::BucketPolicy"},
            )
        ],
    )
