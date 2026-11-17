from pathlib import Path
from unittest.mock import Mock

import pytest
from pycfmodel import parse

from cfripper.model.enums import RuleMode
from cfripper.model.utils import convert_json_or_yaml_to_dict
from cfripper.nested_stack import (
    MissingNestedTemplateException,
    NestedTemplateCycleException,
    NestedTemplateWalker,
    get_nested_stack_template_urls,
    is_remote_template_url,
    iter_nested_templates,
    resolve_local_template_path,
)
from cfripper.rule_processor import RuleProcessor

NESTED_FIXTURE_ROOT = Path(__file__).parent.parent / "test_templates" / "nested"


def _load_cfmodel(path: Path):
    return parse(convert_json_or_yaml_to_dict(path.read_text()))


def _write_template(path: Path, content: str) -> Path:
    path.write_text(content)
    return path


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


# --- Local nested stack traversal -------------------------------------------


def test_walker_discovers_nested_templates_and_keeps_the_nesting_chain():
    walker = NestedTemplateWalker(load_cfmodel=_load_cfmodel)

    root = walker.walk(NESTED_FIXTURE_ROOT / "root_with_deep_chain.yaml")
    nodes = iter_nested_templates(root)

    assert [node.path.name for node in nodes] == [
        "root_with_deep_chain.yaml",
        "middle.yaml",
        "leaf_cross_account.json",
    ]
    middle, leaf = nodes[1], nodes[2]
    assert middle.parents == ["MiddleStack"]
    assert leaf.parents == ["MiddleStack", "LeafStack"]
    assert leaf.nesting_chain("root_with_deep_chain.yaml") == (
        "root_with_deep_chain.yaml > MiddleStack/LeafStack/leaf_cross_account.json"
    )


def test_walker_loads_each_unique_template_only_once():
    load_calls = []

    def counting_loader(path: Path):
        load_calls.append(path)
        return _load_cfmodel(path)

    walker = NestedTemplateWalker(load_cfmodel=counting_loader)
    root = walker.walk(NESTED_FIXTURE_ROOT / "root_with_shared_child.yaml")
    nodes = iter_nested_templates(root)

    assert [node.path.name for node in nodes] == ["root_with_shared_child.yaml", "shared_child.yaml"]
    assert len(load_calls) == 2
    assert len(root.children) == 2
    assert root.children[0] is root.children[1]


def test_walker_fails_closed_on_missing_template(tmp_path: Path):
    root = _write_template(
        tmp_path / "root.yaml",
        """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Child:
    Type: AWS::CloudFormation::Stack
    Properties: {TemplateURL: missing.yaml}
""",
    )

    with pytest.raises(MissingNestedTemplateException, match="missing.yaml"):
        NestedTemplateWalker(load_cfmodel=_load_cfmodel).walk(root)


def test_walker_fails_closed_on_reference_cycle():
    with pytest.raises(NestedTemplateCycleException, match="cycle"):
        NestedTemplateWalker(load_cfmodel=_load_cfmodel).walk(NESTED_FIXTURE_ROOT / "cycle_a.yaml")


def test_walker_skips_remote_and_dynamic_template_urls_but_keeps_scanning(tmp_path: Path):
    root = _write_template(
        tmp_path / "root.yaml",
        """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Remote:
    Type: AWS::CloudFormation::Stack
    Properties: {TemplateURL: https://bucket.s3.amazonaws.com/remote.yaml}
  Dynamic:
    Type: AWS::CloudFormation::Stack
    Properties: {TemplateURL: !Ref ChildUrl}
""",
    )

    root_node = NestedTemplateWalker(load_cfmodel=_load_cfmodel).walk(root)

    assert root_node.children == []


def test_get_nested_stack_template_urls_returns_only_string_local_references():
    model = parse(
        {
            "Resources": {
                "Local": {"Type": "AWS::CloudFormation::Stack", "Properties": {"TemplateURL": "child.yaml"}},
                "Remote": {
                    "Type": "AWS::CloudFormation::Stack",
                    "Properties": {"TemplateURL": "https://example.com/child.yaml"},
                },
                "Dynamic": {
                    "Type": "AWS::CloudFormation::Stack",
                    "Properties": {"TemplateURL": {"Ref": "ChildUrl"}},
                },
                "NotAStack": {"Type": "AWS::S3::Bucket"},
            }
        }
    )

    assert get_nested_stack_template_urls(model) == {
        "Local": "child.yaml",
        "Remote": "https://example.com/child.yaml",
    }


def test_resolve_local_template_path_handles_relative_and_remote_urls(tmp_path: Path):
    parent = tmp_path / "root.yaml"

    assert resolve_local_template_path("sub/child.yaml", parent) == (tmp_path / "sub" / "child.yaml").resolve()
    assert resolve_local_template_path("s3://bucket/child.yaml", parent) is None
    assert is_remote_template_url("https://example.com/t.yaml")
