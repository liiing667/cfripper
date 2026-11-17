__all__ = ["S3BucketPolicyPrincipalRule"]
import logging
from typing import Dict, Optional

from pycfmodel.model.resources.s3_bucket_policy import S3BucketPolicy

from cfripper.model.enums import RuleGranularity, RuleRisk
from cfripper.model.result import Result
from cfripper.model.utils import PrincipalKind, get_principal_identity
from cfripper.rules.base_rules import PrincipalCheckingRule, ResourceSpecificRule

logger = logging.getLogger(__file__)


class S3BucketPolicyPrincipalRule(PrincipalCheckingRule, ResourceSpecificRule):
    """
    Checks for non-allowed principals in S3 bucket policies.

    Risk:
        This is designed to block unintended access from third party accounts to your buckets.

    Fix:
        All principals connected to S3 Bucket Policies should be known. CFRipper checks that **all** principals meet
        the requirements expected. The list of valid accounts is defined in `valid_principals`, which is set in the config.

    Filters context:
        | Parameter   | Type               | Description                                                    |
        |:-----------:|:------------------:|:--------------------------------------------------------------:|
        |`config`     | str                | `config` variable available inside the rule                    |
        |`extras`     | str                | `extras` variable available inside the rule                    |
        |`logical_id` | str                | ID used in Cloudformation to refer the resource being analysed |
        |`resource`   | `S3BucketPolicy`   | Resource that is being addressed                               |
        |`statement`  | `Statement`        | Statement being checked found in the Resource                  |
        |`principal`  | str                | AWS Principal being checked found in the statement             |
        |`account_id` | str                | Account ID found in the principal                              |
    """

    GRANULARITY = RuleGranularity.RESOURCE

    REASON = "S3 Bucket {} policy has non-allowed principals {}"
    RISK_VALUE = RuleRisk.HIGH
    RESOURCE_TYPES = (S3BucketPolicy,)

    def resource_invoke(self, resource: S3BucketPolicy, logical_id: str, extras: Optional[Dict] = None) -> Result:
        result = Result()

        for statement in resource.Properties.PolicyDocument._statement_as_list():
            for principal in statement.get_principal_list():
                identity = get_principal_identity(principal)
                if identity.kind is PrincipalKind.AWS_SERVICE:
                    # AWS service principals are not account identities
                    continue
                if identity.identifier not in self.allowed_principal_identities:
                    if statement.Condition and statement.Condition.dict():
                        # Ignoring condition checks since they will get reviewed in other rules and future improvements
                        pass
                    else:
                        self.add_failure_to_result(
                            result,
                            self.REASON.format(logical_id, identity.identifier),
                            resource_ids={logical_id},
                            resource_types={resource.Type},
                            context={
                                "config": self._config,
                                "extras": extras,
                                "logical_id": logical_id,
                                "resource": resource,
                                "statement": statement,
                                "principal": principal,
                                "account_id": (
                                    identity.identifier if identity.kind is PrincipalKind.ACCOUNT_ID else None
                                ),
                            },
                        )
        return result
