import pytest

from cfripper.model.utils import (
    InvalidURLException,
    PrincipalKind,
    extract_bucket_name_and_path_from_url,
    get_account_id_from_principal,
    get_principal_identity,
)


@pytest.mark.parametrize(
    "template_url, bucket, path",
    [
        ("https://cf-templates.s3.amazonaws.com/path/to/template.yml", "cf-templates", "path/to/template.yml"),
        (
            "https://cf-templates.s3-eu-central-1.amazonaws.com/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
        ("https://s3.amazonaws.com/cf-templates/path/to/template.yml", "cf-templates", "path/to/template.yml"),
        (
            "https://s3.eu-central-1.amazonaws.com/cf-templates/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
        (
            "https://s3-eu-central-1.amazonaws.com/cf-templates/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
        (
            "https://cf-templates.s3.eu-central-1.amazonaws.com/path/to/template.yml",
            "cf-templates",
            "path/to/template.yml",
        ),
    ],
)
def test_extract_bucket_name_and_path_from_url_works(template_url, bucket, path):
    assert extract_bucket_name_and_path_from_url(template_url) == (bucket, path)


@pytest.mark.parametrize(
    "template_url",
    [
        ("https://cf-templatesXs3Xamazonaws.com/path/to/template.yml"),
        ("https://cf-templatesXs3-eu-central-1Xamazonaws.com/path/to/template.yml"),
        ("https://s3Xamazonaws.com/cf-templates/path/to/template.yml"),
        ("https://s3Xeu-central-1XamazonawsXcom/cf-templates/path/to/template.yml"),
        ("https://s3-eu-central-1XamazonawsXcom/cf-templates/path/to/template.yml"),
    ],
)
def test_extract_bucket_name_and_path_from_url_fail(template_url):
    with pytest.raises(InvalidURLException):
        extract_bucket_name_and_path_from_url(template_url)


@pytest.mark.parametrize(
    "principal, expected_kind, expected_identifier",
    [
        # account-like strings
        ("123456789012", PrincipalKind.ACCOUNT_ID, "123456789012"),
        ("12345", PrincipalKind.ACCOUNT_ID, "12345"),
        # IAM ARNs, including role paths
        ("arn:aws:iam::123456789012:root", PrincipalKind.ACCOUNT_ID, "123456789012"),
        ("arn:aws:iam::123456789012:role/path/to/role", PrincipalKind.ACCOUNT_ID, "123456789012"),
        # STS assumed-role ARNs
        ("arn:aws:sts::123456789012:assumed-role/test-role/session", PrincipalKind.ACCOUNT_ID, "123456789012"),
        # other partitions resolve to the same account identity
        ("arn:aws-cn:iam::123456789012:root", PrincipalKind.ACCOUNT_ID, "123456789012"),
        ("arn:aws-us-gov:sts::123456789012:assumed-role/test-role/session", PrincipalKind.ACCOUNT_ID, "123456789012"),
        # case and encoding don't create a second identity
        ("ARN:AWS:IAM::123456789012:ROOT", PrincipalKind.ACCOUNT_ID, "123456789012"),
        ("arn%3Aaws%3Aiam%3A%3A123456789012%3Aroot", PrincipalKind.ACCOUNT_ID, "123456789012"),
        ("  arn:aws:iam::123456789012:root  ", PrincipalKind.ACCOUNT_ID, "123456789012"),
        ("１２３４５６７８９０１２", PrincipalKind.ACCOUNT_ID, "123456789012"),
        # canonical IDs are normalized to lowercase
        (
            "540804c33a284a299d2547575ce1010f2312ef3da9b3a053c8bc45bf233e4353",
            PrincipalKind.CANONICAL_ID,
            "540804c33a284a299d2547575ce1010f2312ef3da9b3a053c8bc45bf233e4353",
        ),
        (
            "540804C33A284A299D2547575CE1010F2312EF3DA9B3A053C8BC45BF233E4353",
            PrincipalKind.CANONICAL_ID,
            "540804c33a284a299d2547575ce1010f2312ef3da9b3a053c8bc45bf233e4353",
        ),
        # AWS services
        ("lambda.amazonaws.com", PrincipalKind.AWS_SERVICE, "lambda.amazonaws.com"),
        ("LAMBDA.AMAZONAWS.COM", PrincipalKind.AWS_SERVICE, "lambda.amazonaws.com"),
        ("lambda.amazonaws.com.cn", PrincipalKind.AWS_SERVICE, "lambda.amazonaws.com.cn"),
        # unknown sources stay unknown (and therefore risky)
        ("*", PrincipalKind.UNKNOWN, "*"),
        ("potato", PrincipalKind.UNKNOWN, "potato"),
        ("GETATT SomeResource.Arn", PrincipalKind.UNKNOWN, "GETATT SomeResource.Arn"),
        ("UNDEFINED_PARAM", PrincipalKind.UNKNOWN, "UNDEFINED_PARAM"),
        ("arn:aws:s3:::my_corporate_bucket", PrincipalKind.UNKNOWN, "arn:aws:s3:::my_corporate_bucket"),
        (
            "arn:aws:iam::aws:policy/AdministratorAccess",
            PrincipalKind.UNKNOWN,
            "arn:aws:iam::aws:policy/AdministratorAccess",
        ),
    ],
)
def test_get_principal_identity(principal, expected_kind, expected_identifier):
    identity = get_principal_identity(principal)
    assert identity.kind is expected_kind
    assert identity.identifier == expected_identifier
    assert identity.source == principal


@pytest.mark.parametrize(
    "principal, expected_account_id",
    [
        ("123456789012", "123456789012"),
        ("arn:aws:iam::123456789012:root", "123456789012"),
        ("arn:aws:sts::123456789012:assumed-role/test-role/session", "123456789012"),
        ("arn:aws-cn:iam::123456789012:root", "123456789012"),
        ("540804c33a284a299d2547575ce1010f2312ef3da9b3a053c8bc45bf233e4353", None),
        ("lambda.amazonaws.com", None),
        ("potato", None),
        ("arn:aws:s3:::my_corporate_bucket", None),
    ],
)
def test_get_account_id_from_principal(principal, expected_account_id):
    assert get_account_id_from_principal(principal) == expected_account_id
