from unittest.mock import Mock

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result, ResultException
from cfripper.rule_processor import RuleProcessor


def test_rule_processor_invoke_rules():
    rule = Mock()
    rule.rule_mode = RuleMode.BLOCKING

    processor = RuleProcessor(rule)

    template = Mock()
    config = Mock()
    processor.process_cf_template(template, config)

    rule.invoke.assert_called()


def test_rule_processor_dont_invoke_disabled_rules():
    rule = Mock()
    rule.rule_mode = RuleMode.DISABLED

    processor = RuleProcessor(rule)

    template = Mock()
    config = Mock()
    processor.process_cf_template(template, config)

    rule.invoke.assert_not_called()


class GoodRule:
    rule_mode = RuleMode.BLOCKING

    def __init__(self, result=None):
        self.result = result or Result()

    def invoke(self, cfmodel, extras):
        self.invoked = True
        return self.result


class CrashingRule:
    rule_mode = RuleMode.BLOCKING

    def invoke(self, cfmodel, extras):
        raise RuntimeError("rule blew up")


def test_rule_processor_records_exception_with_rule_name_and_fails_closed():
    processor = RuleProcessor(CrashingRule())

    result = processor.process_cf_template(Mock(), Mock())

    assert result.exceptions == [
        ResultException(
            rule="CrashingRule",
            exception_type="RuntimeError",
            exception_message="rule blew up",
        )
    ]
    assert result.valid is False


def test_rule_processor_continues_with_remaining_rules_after_a_crash():
    good_rule = GoodRule()
    processor = RuleProcessor(CrashingRule(), good_rule)

    result = processor.process_cf_template(Mock(), Mock())

    # The crash must not abort the scan: later rules still run and their
    # findings merge into the same result, while the crash is still recorded.
    assert good_rule.invoked is True
    assert len(result.exceptions) == 1
    assert result.exceptions[0].rule == "CrashingRule"
    assert result.valid is False


def test_rule_processor_merges_results_when_no_rule_crashes():
    healthy_result = Result()
    healthy_result.add_failure(
        rule="GoodRule",
        reason="finding",
        rule_mode=RuleMode.MONITOR,
        risk_value=RuleRisk.LOW,
        granularity=RuleGranularity.STACK,
    )
    processor = RuleProcessor(GoodRule(healthy_result))

    result = processor.process_cf_template(Mock(), Mock())

    assert result.exceptions == []
    assert [failure.rule for failure in result.failures] == ["GoodRule"]
    assert result.valid is True
