from unittest.mock import Mock

import pycfmodel

from cfripper.config.config import Config
from cfripper.model.enums import RuleMode
from cfripper.rule_processor import RuleProcessor
from cfripper.rules.wildcard_principals import FullWildcardPrincipalRule, PartialWildcardPrincipalRule
from cfripper.rules.wildcard_resource_rule import WildcardResourceRule
from tests.utils import get_cfmodel_from


def _static_cfmodel():
    return pycfmodel.parse({"Resources": {"MockBucket": {"Type": "AWS::S3::Bucket"}}})


def test_rule_processor_invoke_rules():
    rule = Mock()
    rule.rule_mode = RuleMode.BLOCKING

    processor = RuleProcessor(rule)

    template = _static_cfmodel()
    config = Mock()
    processor.process_cf_template(template, config)

    rule.invoke.assert_called()


def test_rule_processor_dont_invoke_disabled_rules():
    rule = Mock()
    rule.rule_mode = RuleMode.DISABLED

    processor = RuleProcessor(rule)

    template = _static_cfmodel()
    config = Mock()
    processor.process_cf_template(template, config)

    rule.invoke.assert_not_called()


def test_rule_processor_evaluates_every_fn_if_branch_with_locatable_findings():
    processor = RuleProcessor(
        FullWildcardPrincipalRule(Config(rules=["FullWildcardPrincipalRule"])),
        PartialWildcardPrincipalRule(Config(rules=["PartialWildcardPrincipalRule"])),
        WildcardResourceRule(Config(rules=["WildcardResourceRule"])),
    )
    cfmodel = get_cfmodel_from("model/conditional/iam_role_fn_if_principal_resource.json")

    result = processor.process_cf_template(cfmodel, Config())

    branch_paths = {"IsProd[true]": False, "IsProd[false]": False}
    for failure in result.failures:
        for branch in branch_paths:
            if f"conditional branch: {branch}" in failure.reason:
                branch_paths[branch] = True

    # Both branches are evaluated and produce their own locatable findings.
    assert all(branch_paths.values())
    false_branch = [failure for failure in result.failures if "IsProd[false]" in failure.reason]
    true_branch = [failure for failure in result.failures if "IsProd[true]" in failure.reason]
    assert {failure.rule for failure in false_branch} == {"FullWildcardPrincipalRule", "WildcardResourceRule"}
    assert {failure.rule for failure in true_branch} == {"PartialWildcardPrincipalRule"}
    assert not result.valid


def test_rule_processor_keeps_unknown_branch_values_conservative():
    rule = FullWildcardPrincipalRule(Config(rules=["FullWildcardPrincipalRule"]))
    processor = RuleProcessor(rule)
    cfmodel = get_cfmodel_from("model/conditional/iam_role_unknown_ref_in_branch.json")

    result = processor.process_cf_template(cfmodel, Config())

    # The branch backed by an unresolvable Ref is rendered as "*" and flagged.
    flagged_branches = {
        failure.reason.split("conditional branch: ")[1].rstrip("]")
        for failure in result.failures
        if failure.rule == "FullWildcardPrincipalRule"
    }
    assert "UseExternalTrust[true" in flagged_branches
    assert not result.valid


def test_rule_processor_static_template_finding_reason_has_no_branch_suffix():
    rule = FullWildcardPrincipalRule(Config(rules=["FullWildcardPrincipalRule"]))
    processor = RuleProcessor(rule)
    cfmodel = pycfmodel.parse(
        {
            "Resources": {
                "StaticRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Principal": "*",
                                }
                            ]
                        }
                    },
                }
            }
        }
    )

    result = processor.process_cf_template(cfmodel, Config())

    assert result.failures
    assert all("conditional branch" not in failure.reason for failure in result.failures)
