import pytest
from pycfmodel.model.resources.properties.statement_condition import StatementCondition

from cfripper.rules.condition_helpers import condition_restricts_principal


def condition(condition_dict):
    return StatementCondition(**condition_dict)


@pytest.mark.parametrize(
    "condition_dict",
    [
        ({"StringEquals": {"aws:SourceAccount": "123456789012"}}),
        ({"StringEquals": {"aws:PrincipalAccount": ["123456789012", "210987654321"]}}),
        ({"StringEqualsIgnoreCase": {"aws:SourceAccount": "123456789012"}}),
        ({"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"}}),
        ({"StringEquals": {"aws:PrincipalOrgPaths": "o-a1b2c3d4e5/ou-abcd-1234-efgh"}}),
        ({"ArnEquals": {"aws:SourceArn": "arn:aws:sns:eu-west-1:123456789012:source-topic"}}),
        ({"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/app-role"}}),
        (
            {
                "StringEquals": {"aws:SourceAccount": "123456789012", "aws:PrincipalOrgID": "o-a1b2c3d4e5"},
                "ArnEquals": {"aws:SourceArn": "arn:aws:sns:eu-west-1:123456789012:source-topic"},
            }
        ),
    ],
)
def test_condition_is_recognised_as_principal_narrowing(condition_dict):
    assert condition_restricts_principal(condition(condition_dict)) is True


@pytest.mark.parametrize(
    "condition_dict",
    [
        # Set quantifiers can be satisfied by an unrestricted principal when the key is missing
        ({"ForAllValues:StringEquals": {"aws:PrincipalOrgID": ["o-a1b2c3d4e5"]}}),
        ({"ForAnyValue:StringEquals": {"aws:PrincipalAccount": ["123456789012"]}}),
        # Negated operators do not identify an allowed principal
        ({"StringNotEquals": {"aws:SourceAccount": "123456789012"}}),
        ({"ArnNotLike": {"aws:SourceArn": "arn:aws:sns:eu-west-1:123456789012:source-topic"}}),
        # IfExists operators and Null do not guarantee the key is present
        ({"StringEqualsIfExists": {"aws:SourceAccount": "123456789012"}}),
        ({"Null": {"aws:PrincipalAccount": "false"}}),
        # Wildcard or malformed values do not prove a concrete identity
        ({"ArnLike": {"aws:SourceArn": "arn:aws:s3:::*"}}),
        ({"StringEquals": {"aws:SourceAccount": "12345"}}),
        ({"StringEquals": {"aws:PrincipalOrgID": "not-an-org"}}),
        ({"ArnEquals": {"aws:PrincipalArn": "not-an-arn"}}),
        # Conditions on parameters unrelated to the principal identity
        ({"Bool": {"aws:SecureTransport": "true"}}),
        ({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}),
        ({"StringEquals": {"s3:x-amz-server-side-encryption": "AES256"}}),
        # `aws:userid` is not an account, organisation or principal ARN, so it cannot prove narrowing
        ({"StringLike": {"aws:userid": ["AROAID2GEXAMPLEROLEID:*", "444455556666"]}}),
        # Unresolved CloudFormation intrinsic functions
        ({"ArnEquals": {"aws:SourceArn": {"Fn::Sub": "arn:aws:s3:::${BucketName}"}}}),
        ({"ArnEquals": {"aws:SourceArn": "arn:aws:s3:::${BucketName}"}}),
        ({"StringEquals": {"aws:SourceAccount": "UNDEFINED_PARAM_AccountId"}}),
        ({"ArnEquals": {"aws:SourceArn": "GETATT"}}),
        # Identity key combined with an operator that cannot prove narrowing
        (
            {
                "StringEquals": {"aws:SourceAccount": "123456789012"},
                "Bool": {"aws:SecureTransport": "true"},
            }
        ),
        (
            {
                "StringEquals": {"aws:SourceAccount": "123456789012", "s3:x-amz-server-side-encryption": "AES256"},
            }
        ),
        # Empty values cannot prove anything
        ({"StringEquals": {"aws:SourceAccount": []}}),
        ({}),
    ],
)
def test_condition_is_not_recognised_as_principal_narrowing(condition_dict):
    assert condition_restricts_principal(condition(condition_dict)) is False
