import pytest

from cfripper.model.conditional_expansion import (
    MAX_BRANCH_VARIANTS,
    UNKNOWN_VALUE,
    expand_conditional_cfmodel,
    expand_conditional_template,
    normalise_unknown_policy_values,
)
from tests.utils import get_cfmodel_from


def test_static_template_returns_single_unchanged_variant():
    template = {"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}

    variants = expand_conditional_template(template)

    assert len(variants) == 1
    branch_path, expanded = variants[0]
    assert branch_path == ()
    assert expanded == template
    assert expanded is not template


def test_fn_if_produces_one_variant_per_branch_with_locatable_path():
    template = {
        "Conditions": {"IsProd": {"Fn::Equals": ["a", "b"]}},
        "Resources": {
            "Role": {
                "Properties": {
                    "PolicyDocument": {
                        "Statement": [
                            {"Resource": {"Fn::If": ["IsProd", "safe-arn", "*"]}},
                        ]
                    }
                }
            }
        },
    }

    variants = expand_conditional_template(template)

    assert len(variants) == 2
    branch_paths = [path for path, _ in variants]
    assert branch_paths == [("IsProd[true]",), ("IsProd[false]",)]
    resources = {
        path: variant["Resources"]["Role"]["Properties"]["PolicyDocument"]["Statement"][0]["Resource"]
        for path, variant in variants
    }
    assert resources == {("IsProd[true]",): "safe-arn", ("IsProd[false]",): "*"}


def test_multiple_conditions_grow_branch_combinations_consistently():
    template = {
        "Resources": {
            "R": {
                "Properties": {
                    "A": {"Fn::If": ["C1", "a1", "a2"]},
                    "B": {"Fn::If": ["C2", "b1", "b2"]},
                }
            }
        }
    }

    variants = expand_conditional_template(template)

    assert len(variants) == 4
    paths = {path for path, _ in variants}
    assert paths == {
        ("C1[true]", "C2[true]"),
        ("C1[true]", "C2[false]"),
        ("C1[false]", "C2[true]"),
        ("C1[false]", "C2[false]"),
    }
    # Both Fn::If nodes follow the same truth assignment inside one variant.
    for path, variant in variants:
        props = variant["Resources"]["R"]["Properties"]
        assert props["A"] == ("a1" if "C1[true]" in path else "a2")
        assert props["B"] == ("b1" if "C2[true]" in path else "b2")


def test_unresolvable_intrinsics_become_unknown_value():
    template = {
        "Conditions": {"Enabled": {"Fn::Equals": ["true", "true"]}},
        "Resources": {
            "R": {
                "Properties": {
                    "RefValue": {"Fn::If": ["Enabled", {"Ref": "BucketName"}, "x"]},
                    "GetAttValue": {"Fn::If": ["Enabled", {"Fn::GetAtt": ["Bucket", "Arn"]}, "x"]},
                    "JoinWithRef": {"Fn::If": ["Enabled", {"Fn::Join": [":", ["arn", {"Ref": "Bucket"}]]}, "x"]},
                    "ConcreteSub": {"Fn::If": ["Enabled", {"Fn::Sub": "arn:aws:s3:::fixed-bucket/*"}, "x"]},
                }
            }
        },
    }

    variants = expand_conditional_template(template)

    true_variant = next(variant for path, variant in variants if path == ("Enabled[true]",))
    props = true_variant["Resources"]["R"]["Properties"]
    assert props["RefValue"] == UNKNOWN_VALUE
    assert props["GetAttValue"] == UNKNOWN_VALUE
    assert props["JoinWithRef"] == UNKNOWN_VALUE
    # A parameter-free Fn::Sub still describes one concrete string.
    assert props["ConcreteSub"] == {"Fn::Sub": "arn:aws:s3:::fixed-bucket/*"}


def test_static_template_keeps_opaque_function_dicts_untouched():
    template = {
        "Resources": {
            "R": {
                "Properties": {
                    "RefValue": {"Ref": "BucketName"},
                    "JoinWithRef": {"Fn::Join": [":", ["arn", {"Ref": "Bucket"}]]},
                }
            }
        }
    }

    variants = expand_conditional_template(template)

    assert len(variants) == 1
    _, expanded = variants[0]
    props = expanded["Resources"]["R"]["Properties"]
    assert props["RefValue"] == {"Ref": "BucketName"}
    assert props["JoinWithRef"] == {"Fn::Join": [":", ["arn", {"Ref": "Bucket"}]]}


def test_nested_fn_if_and_malformed_body_are_conservative():
    nested = {
        "Resources": {
            "R": {"Properties": {"Resource": {"Fn::If": ["C1", {"Fn::If": ["C2", "safe", {"Ref": "Bucket"}]}, "*"]}}}
        }
    }

    variants = dict(expand_conditional_template(nested))
    assert variants[("C1[true]", "C2[true]")]["Resources"]["R"]["Properties"]["Resource"] == "safe"
    assert variants[("C1[true]", "C2[false]")]["Resources"]["R"]["Properties"]["Resource"] == UNKNOWN_VALUE
    assert variants[("C1[false]", "C2[true]")]["Resources"]["R"]["Properties"]["Resource"] == "*"
    assert variants[("C1[false]", "C2[false]")]["Resources"]["R"]["Properties"]["Resource"] == "*"

    malformed = {"Resources": {"R": {"Properties": {"Resource": {"Fn::If": ["C"]}}}}}
    for _, variant in expand_conditional_template(malformed):
        assert variant["Resources"]["R"]["Properties"]["Resource"] == UNKNOWN_VALUE


def test_branch_variant_cap_falls_back_to_unknown_values():
    over_cap = int(MAX_BRANCH_VARIANTS.bit_length())
    template = {
        "Resources": {
            f"Resource{index}": {"Properties": {"Value": {"Fn::If": [f"Condition{index}", "safe", "unsafe"]}}}
            for index in range(over_cap)
        }
    }

    variants = expand_conditional_template(template)

    assert len(variants) == 1
    branch_path, fallback = variants[0]
    assert branch_path == ("unresolved-conditions",)
    assert fallback["Resources"]["Resource0"]["Properties"]["Value"] == UNKNOWN_VALUE


def test_normalise_unknown_policy_values_replaces_residual_functions():
    template = {
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [{"Ref": "ActionName"}, "s3:GetObject"],
                                "Resource": {"Fn::GetAtt": ["Bucket", "Arn"]},
                                "Principal": {"AWS": {"Fn::ImportValue": "TrustArn"}},
                            }
                        ]
                    }
                },
            }
        }
    }

    normalised = normalise_unknown_policy_values(template)
    statement = normalised["Resources"]["Role"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]

    assert statement["Action"] == [UNKNOWN_VALUE, "s3:GetObject"]
    assert statement["Resource"] == UNKNOWN_VALUE
    assert statement["Principal"] == {"AWS": UNKNOWN_VALUE}
    # Input is untouched.
    assert template["Resources"]["Role"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]["Resource"] == {
        "Fn::GetAtt": ["Bucket", "Arn"]
    }


def test_normalise_keeps_concrete_function_strings():
    template = {
        "Resources": {
            "Policy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::fixed/*"},
                                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                            }
                        ]
                    }
                },
            }
        }
    }

    statement = normalise_unknown_policy_values(template)["Resources"]["Policy"]["Properties"]["PolicyDocument"][
        "Statement"
    ][0]

    assert statement["Resource"] == {"Fn::Sub": "arn:aws:s3:::fixed/*"}
    assert statement["Principal"] == {"AWS": "arn:aws:iam::123456789012:root"}


def test_expand_conditional_cfmodel_yields_parseable_branch_models(get_cfmodel):
    cfmodel = get_cfmodel("model/conditional/iam_role_fn_if_principal_resource.json")

    variants = expand_conditional_cfmodel(cfmodel)

    assert len(variants) == 2
    assert {path for path, _ in variants} == {("IsProd[true]",), ("IsProd[false]",)}
    for path, branch_model in variants:
        role = branch_model.Resources["ConditionalRole"]
        principal = role.Properties.AssumeRolePolicyDocument.statement_as_list()[0].get_principal_list()
        resource = role.Properties.Policies[0].PolicyDocument.statement_as_list()[0].get_resource_list()
        assert all(isinstance(value, str) for value in principal + resource)


@pytest.fixture()
def get_cfmodel():
    return get_cfmodel_from
