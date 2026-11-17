import json
import logging
import re
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Optional
from urllib.parse import unquote

import boto3
import yaml
from cfn_flip import to_json
from pycfmodel.model.resources.properties.policy import Policy

from cfripper.config.regex import REGEX_ARN, REGEX_IAM_ARN, REGEX_STS_ARN

logger = logging.getLogger(__file__)


class InvalidURLException(Exception):
    pass


def extract_bucket_name_and_path_from_url(url):
    # Remove query string
    url = unquote(url).split("?")[0]

    bucket_name = None
    path = None

    # https://bucket.s3.amazonaws.com/path1/path2
    match = re.search(r"^https://([^.]+)\.s3\.amazonaws\.com(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://bucket.s3.aws-region.amazonaws.com/path1/path2
    match = re.search(r"^https://([^.]+)\.s3\.[^\.]+\.amazonaws\.com(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://bucket.s3-aws-region.amazonaws.com/path1/path2
    match = re.search(r"^https://([^.]+)\.s3-[^\.]+\.amazonaws\.com(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://s3.amazonaws.com/bucket/path1/path2
    match = re.search(r"^https://s3\.amazonaws\.com/([^\/]+)(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://s3.aws-region.amazonaws.com/bucket/path1/path2
    match = re.search(r"^https://s3\.[^.]+\.amazonaws\.com/([^\/]+)(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    # https://s3-aws-region.amazonaws.com/bucket/path1/path2
    match = re.search(r"^https://s3-[^.]+\.amazonaws\.com/([^\/]+)(.*?)$", url)
    if match:
        bucket_name, path = match.group(1), match.group(2)[1:]  # Trim start /

    if bucket_name is None and path is None:
        raise InvalidURLException(f"Couldn't extract bucket name and path from url: {url}")

    logger.info(f"extract_bucket_name_and_path_from_url. returning for {bucket_name} and {path} for {url}")

    return bucket_name, path


def convert_json_or_yaml_to_dict(file_content, stack_id: Optional[str] = None):
    with suppress(ValueError):
        return json.loads(file_content)

    try:
        # Convert file_content (assuming that is YAML) to JSON if possible
        file_content = to_json(file_content)
        return json.loads(file_content)
    except yaml.YAMLError:
        logger.exception(f"Could not convert YAML to JSON template for {stack_id}")
    except ValueError:
        logger.exception(f"Could not parse JSON template for {stack_id}")

    return None


@lru_cache(maxsize=None)
def get_managed_policy(managed_policy_arn):
    iam_client = boto3.client("iam")
    managed_policy = iam_client.get_policy(PolicyArn=managed_policy_arn)
    version_id = managed_policy.get("Policy", {}).get("DefaultVersionId")
    if version_id:
        policy_version = iam_client.get_policy_version(PolicyArn=managed_policy_arn, VersionId=version_id)
        return Policy(
            **{
                "PolicyDocument": policy_version["PolicyVersion"]["Document"],
                "PolicyName": f"AutoTransformedManagedPolicy{version_id}",
            }
        )
    return None


def get_aws_service_from_arn(arn: str) -> Optional[str]:
    match = REGEX_ARN.match(arn)
    if match:
        return match.group(1)
    return None


def get_account_id_from_arn(arn: str) -> Optional[str]:
    match = REGEX_ARN.match(arn)
    if match:
        return match.group(3)
    return None


def get_account_id_from_iam_arn(arn: str) -> Optional[str]:
    match = REGEX_IAM_ARN.match(arn)
    if match:
        return match.group(1)
    return None


def get_account_id_from_sts_arn(arn: str) -> Optional[str]:
    match = REGEX_STS_ARN.match(arn)
    if match:
        return match.group(1)
    return None


class PrincipalKind(str, Enum):
    """Types of identities a principal value can resolve to."""

    ACCOUNT_ID = "account_id"
    CANONICAL_ID = "canonical_id"
    AWS_SERVICE = "aws_service"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PrincipalIdentity:
    """
    Normalized identity behind a raw principal value.

    `identifier` is the comparable form of the identity (account id, canonical id,
    service name or normalized principal) while `source` keeps the original value
    for reporting.
    """

    kind: PrincipalKind
    identifier: str
    source: str


"""
Check for ARNs from any AWS partition (aws, aws-cn, aws-us-gov, ...).
The ARN scheme and service are matched case-insensitively so that case
differences don't make the same identity look like two different ones.
Groups: partition, service, region, account id, resource.
"""
REGEX_PRINCIPAL_ARN = re.compile(r"^arn:([^:]+):([^:]+):([^:]*):([^:]*):(.+)$", re.IGNORECASE)

"""
Check for canonical user IDs (64 hexadecimal characters, any casing).
"""
REGEX_CANONICAL_ID = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

AWS_SERVICE_PRINCIPAL_SUFFIXES = (".amazonaws.com", ".amazonaws.com.cn")


def normalize_principal(principal: str) -> str:
    """
    Return the canonical form of a principal so that encoding and compatibility
    differences (percent-encoding, unicode compatibility characters such as
    full-width digits, surrounding whitespace) don't create duplicate identities
    for the same source.
    """
    return unicodedata.normalize("NFKC", unquote(principal)).strip()


def get_principal_identity(principal: str) -> PrincipalIdentity:
    """
    Single, reviewable conversion from a raw principal to the identity behind it.

    Every rule that needs to know *who* a principal is should use this function
    instead of re-implementing its own parsing. Sources that can't be resolved
    are returned as `PrincipalKind.UNKNOWN` so callers keep treating them as risky
    instead of silently allowing them.
    """
    normalized = normalize_principal(principal)

    if normalized.isascii() and normalized.isdigit():
        return PrincipalIdentity(PrincipalKind.ACCOUNT_ID, normalized, principal)

    arn_match = REGEX_PRINCIPAL_ARN.match(normalized)
    if arn_match:
        _partition, service, _region, account_id, _resource = arn_match.groups()
        if service.lower() in ("iam", "sts") and account_id.isascii() and account_id.isdigit():
            return PrincipalIdentity(PrincipalKind.ACCOUNT_ID, account_id, principal)
        return PrincipalIdentity(PrincipalKind.UNKNOWN, normalized, principal)

    if REGEX_CANONICAL_ID.match(normalized):
        return PrincipalIdentity(PrincipalKind.CANONICAL_ID, normalized.lower(), principal)

    if normalized.lower().endswith(AWS_SERVICE_PRINCIPAL_SUFFIXES):
        return PrincipalIdentity(PrincipalKind.AWS_SERVICE, normalized.lower(), principal)

    return PrincipalIdentity(PrincipalKind.UNKNOWN, normalized, principal)


def get_account_id_from_principal(principal: str) -> Optional[str]:
    identity = get_principal_identity(principal)
    if identity.kind is PrincipalKind.ACCOUNT_ID:
        return identity.identifier
    return None
