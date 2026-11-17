import json
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree as ET

import click
import pytest
from click.testing import CliRunner

import cfripper.cli as undertest
from cfripper.cli import format_result, format_result_junit
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Result
from tests.utils import FIXTURE_ROOT_PATH

NESTED_FIXTURE_PATH = FIXTURE_ROOT_PATH / "nested"


def _runner_output(result, capsys) -> str:
    """Return CLI output regardless of which capture layer holds it.

    Depending on whether an earlier test reconfigured logging (pytest's live
    logging then suspends global capture while a ``CliRunner`` command runs),
    the command's stdout is either held by the runner or by pytest's ``capsys``.
    Merging both keeps the assertions independent of test ordering.
    """
    captured = capsys.readouterr()
    return result.output + captured.out + captured.err


@pytest.mark.parametrize(
    "aws_account_id_arg, validation_result",
    [(None, None), ("", None), ("123456789012", "123456789012")],
)
def test_validate_aws_account_id(
    aws_account_id_arg,
    validation_result,
):
    fake_command = click.Command("fake_command")
    fake_context = click.Context(fake_command)
    fake_param = "fake_param"
    assert undertest.validate_aws_account_id(fake_context, fake_param, aws_account_id_arg) == validation_result


def test_validate_aws_account_id_with_malformed_arg():
    fake_command = click.Command("fake_command")
    fake_context = click.Context(fake_command)
    fake_param = "fake_param"

    with pytest.raises(click.BadParameter):
        undertest.validate_aws_account_id(fake_context, fake_param, "malformed aws account id")


@pytest.mark.parametrize(
    "aws_principals_arg, validation_result",
    [
        (None, None),
        ("", None),
        ("123456789012", ["123456789012"]),
        (
            "arn:aws:iam::123456789012:root,234567890123,arn:aws:iam::111222333444:user/user-name",
            ["arn:aws:iam::123456789012:root", "234567890123", "arn:aws:iam::111222333444:user/user-name"],
        ),
    ],
)
def test_validate_aws_principals(
    aws_principals_arg,
    validation_result,
):
    fake_command = click.Command("fake_command")
    fake_context = click.Context(fake_command)
    fake_param = "fake_param"
    assert undertest.validate_aws_principals(fake_context, fake_param, aws_principals_arg) == validation_result


@patch("cfripper.cli.process_template")
def test_aws_account_id_cli_option(patched_process_template: MagicMock):
    patched_process_template.return_value = True
    test_template_path = str(FIXTURE_ROOT_PATH) + "/others/iam_role.json"
    fake_aws_account_id = "123456789012"

    runner = CliRunner()
    result = runner.invoke(undertest.cli, ["--aws-account-id", fake_aws_account_id, test_template_path])
    assert patched_process_template.call_count == 1
    assert patched_process_template.call_args[1]["aws_account_id"] == fake_aws_account_id
    assert result.exit_code == 0


@patch("cfripper.cli.process_template")
def test_aws_principles_cli_option(patched_process_template: MagicMock):
    patched_process_template.return_value = True
    test_template_path = str(FIXTURE_ROOT_PATH) + "/others/iam_role.json"
    fake_aws_principals = ["123456789012", "234567890123"]

    runner = CliRunner()
    result = runner.invoke(undertest.cli, ["--aws-principals", ",".join(fake_aws_principals), test_template_path])
    assert patched_process_template.call_count == 1
    assert patched_process_template.call_args[1]["aws_principals"] == fake_aws_principals
    assert result.exit_code == 0


# --- JUnitXML output (#186) --------------------------------------------------


@pytest.fixture
def result_with_failures() -> Result:
    """A Result carrying one blocking failure and one monitored failure."""

    result = Result()
    result.add_failure(
        rule="PolicyOnUserRule",
        reason="IAM policy should not apply directly to users",
        rule_mode=RuleMode.BLOCKING,
        risk_value=RuleRisk.MEDIUM,
        granularity=RuleGranularity.RESOURCE,
        resource_ids={"DirectPolicy"},
        resource_types={"AWS::IAM::Policy"},
    )
    result.add_failure(
        rule="PrivilegeEscalationRule",
        reason="blacklisted IAM actions",
        rule_mode=RuleMode.MONITOR,
        risk_value=RuleRisk.HIGH,
        granularity=RuleGranularity.RESOURCE,
        actions={"iam:CreateAccessKey"},
    )
    return result


def test_format_result_junit_is_well_formed_xml(result_with_failures: Result):
    # Given a result carrying one blocking and one monitored failure.
    # When it is rendered as JUnit and re-parsed.
    xml = format_result_junit(result_with_failures, template_name="template.yaml")
    root = ET.fromstring(xml)
    cases = root.findall("testcase")
    # `Result.failures` has no documented ordering, so the names are collected
    # order-independently: asserting on the iteration order would be fragile.
    case_names = sorted(case.attrib["name"] for case in cases)
    failure_nodes = [case.find("failure") for case in cases]
    direct_policy = {case.attrib["name"]: case for case in cases}["PolicyOnUserRule"].find("failure")

    # Then the suite describes both failures.
    assert root.tag == "testsuite"
    assert root.attrib["name"] == "template.yaml"
    assert root.attrib["tests"] == "2"
    assert root.attrib["failures"] == "2"
    assert root.attrib["errors"] == "0"
    assert case_names == ["PolicyOnUserRule", "PrivilegeEscalationRule"]
    # Each case carries a <failure> child, which is what a reporter counts.
    assert all(node is not None for node in failure_nodes)
    assert direct_policy is not None
    assert direct_policy.attrib["type"] == "MEDIUM"
    # The full detail lives in the element text, not only in the message.
    assert direct_policy.text is not None
    assert "resource_ids: DirectPolicy" in direct_policy.text


def test_format_result_junit_escapes_reasons_and_resource_ids():
    """Reasons embed template fragments, so output must survive XML metacharacters.

    The report is parsed by CI tooling; a reason containing `<` or `&` must be
    escaped rather than producing invalid XML or injecting a node.
    """
    # Given a failure whose reason and resource id both carry XML
    # metacharacters and a closing tag.
    result = Result()
    result.add_failure(
        rule="SomeRule",
        reason='value <not escaped> & "quoted" </failure><injected/>',
        rule_mode=RuleMode.BLOCKING,
        risk_value=RuleRisk.HIGH,
        granularity=RuleGranularity.RESOURCE,
        resource_ids={"<weird & id>"},
    )

    # When it is rendered and re-parsed (which raises if the escaping is wrong).
    root = ET.fromstring(format_result_junit(result))
    cases = root.findall("testcase")
    injected = root.findall(".//injected")
    text = root.find("testcase").find("failure").text

    # Then the metacharacters survive as text and no node was injected.
    # The search covers the whole tree: a bare `findall("injected")` would only
    # look at direct children of the suite and miss one nested under a <testcase>.
    assert len(cases) == 1
    assert injected == []
    assert text is not None
    assert "<not escaped>" in text
    assert "<weird & id>" in text


def test_format_result_junit_reports_a_clean_template_as_zero_cases():
    # Given a result with no failures and no exceptions.
    # When it is rendered as JUnit and re-parsed.
    root = ET.fromstring(format_result_junit(Result()))
    cases = root.findall("testcase")

    # Then the suite reports nothing to run.
    assert root.attrib["tests"] == "0"
    assert root.attrib["failures"] == "0"
    assert cases == []


def test_format_result_junit_reports_exceptions_as_errors():
    """An exception is the scan failing, not a rule violation — hence <error>."""
    # Given a result carrying one exception.
    result = Result()
    result.add_exception(ValueError("could not parse template"))

    # When it is rendered as JUnit and re-parsed.
    root = ET.fromstring(format_result_junit(result))
    error = root.find("testcase").find("error")

    # Then the exception is reported as an error rather than a failure.
    assert root.attrib["errors"] == "1"
    assert root.attrib["failures"] == "0"
    assert error is not None
    assert error.attrib["type"] == "ValueError"


def test_format_result_dispatches_junit(result_with_failures: Result):
    # Given a result and the name of the JUnit format.
    # When the dispatcher renders it.
    xml = format_result(result_with_failures, "junit", template_name="t.yaml")

    # Then the JUnit renderer produced a suite named after the template.
    assert xml.startswith("<testsuite")
    assert 'name="t.yaml"' in xml


def test_cli_accepts_junit_format_and_names_the_suite_after_the_template():
    """The option reaches the formatter with the template name, through the CLI."""
    # Given the CLI invoked on a template with --format junit.
    template = FIXTURE_ROOT_PATH / "others" / "iam_policy_on_user.json"
    runner = CliRunner()
    with patch("cfripper.cli.process_template") as patched:
        patched.return_value = True
        result = runner.invoke(undertest.cli, [str(template), "--format", "junit"])
    output_format = patched.call_args[1]["output_format"]

    # Then the option reached the formatter as "junit".
    # The formatter is called with the template's file name, not its full path,
    # so a report from several templates stays readable.
    assert result.exit_code == 0, result.output
    assert output_format == "junit"


# --- Nested stack packages --------------------------------------------------


def test_cli_scans_nested_templates_and_reports_findings_with_a_nesting_prefix(capsys):
    # Given a clean root template whose child contains a wildcard principal.
    runner = CliRunner()

    # When the CLI scans the package.
    result = runner.invoke(
        undertest.cli,
        [str(NESTED_FIXTURE_PATH / "root_with_wildcard_child.json"), "--format", "txt"],
    )

    # Then the child template is scanned and its blocking failure makes the
    # whole package invalid, with the nesting chain attached to the reason.
    assert result.exit_code == 2, result.output
    output = _runner_output(result, capsys)
    assert "FullWildcardPrincipalRule" in output
    assert "[root_with_wildcard_child.json > ChildStack/child_with_wildcard_principal.json]" in output


def test_cli_follows_deeply_nested_templates_through_subdirectories(capsys):
    # Given a root -> sub/middle -> sub/leaf chain spanning directories.
    runner = CliRunner()

    # When the CLI scans the package with an account id so cross-account trust
    # is evaluated against a known home account.
    result = runner.invoke(
        undertest.cli,
        [str(NESTED_FIXTURE_PATH / "root_with_deep_chain.yaml"), "--aws-account-id", "123456789012"],
    )

    # Then the leaf is reached and its cross-account trust is reported.
    assert result.exit_code == 2, result.output
    output = _runner_output(result, capsys)
    assert "CrossAccountTrustRule" in output
    assert "MiddleStack/LeafStack/leaf_cross_account.json" in output


def test_cli_clean_nested_package_is_valid_and_keeps_single_template_output_shape(capsys):
    # Given a root and child without blocking findings.
    runner = CliRunner()

    # When the CLI scans them as JSON, the format used by automation.
    result = runner.invoke(
        undertest.cli,
        [str(NESTED_FIXTURE_PATH / "clean_root.json"), "--format", "json"],
    )

    # Then the package is valid and the output schema is the plain Result one.
    assert result.exit_code == 0, result.output
    payload = json.loads(_runner_output(result, capsys))
    assert set(payload.keys()) == {"exceptions", "failures"}


def test_cli_missing_nested_template_fails_closed(capsys):
    # Given a package whose local TemplateURL target does not exist.
    runner = CliRunner()

    # When the CLI scans it.
    result = runner.invoke(undertest.cli, [str(NESTED_FIXTURE_PATH / "root_missing_child.json")])

    # Then the run fails (exit 1, scan error) rather than passing on the root.
    assert result.exit_code == 1
    assert "does not exist" in _runner_output(result, capsys)


def test_cli_nested_template_cycle_fails_closed(capsys):
    # Given two templates referencing each other.
    runner = CliRunner()

    # When the CLI scans the package.
    result = runner.invoke(undertest.cli, [str(NESTED_FIXTURE_PATH / "cycle_a.yaml")])

    # Then the cycle is reported as a scan error and the run fails closed.
    assert result.exit_code == 1
    assert "cycle" in _runner_output(result, capsys).lower()


def test_cli_remote_and_dynamic_template_urls_do_not_break_the_scan(capsys):
    # Given a root that only references a remote URL and an intrinsic Ref,
    # neither of which can be mapped to a local file.
    runner = CliRunner()

    # When the CLI scans it.
    result = runner.invoke(undertest.cli, [str(NESTED_FIXTURE_PATH / "root_with_remote_child.json")])
    _runner_output(result, capsys)

    # Then the root itself is still scanned and no failure is raised for the
    # unreachable references.
    assert result.exit_code == 0, result.output
