import logging
from typing import Dict, Optional, Tuple

from pycfmodel.model.cf_model import CFModel

from cfripper.config.config import Config
from cfripper.model.conditional_expansion import expand_conditional_cfmodel
from cfripper.model.enums import RuleMode
from cfripper.model.result import Result

logger = logging.getLogger(__file__)


class RuleProcessor:
    def __init__(self, *args):
        self.rules = args

    def process_cf_template(self, cfmodel: CFModel, config: Config, extras: Optional[Dict] = None) -> Result:
        # A plain static template produces exactly one, unchanged variant, so
        # historical finding ids and rule output are preserved. Templates with
        # `Fn::If` produce one variant per branch combination; every branch is
        # evaluated independently so an insecure branch cannot hide behind the
        # function's string shell.
        branch_variants = expand_conditional_cfmodel(cfmodel)
        if len(branch_variants) == 1:
            return self._invoke_rules(cfmodel, config, extras)

        result = Result()
        for branch_path, branch_model in branch_variants:
            branch_result = self._invoke_rules(branch_model, config, extras)
            self._annotate_branch(branch_result, branch_path)
            result += branch_result
        return result

    def _invoke_rules(self, cfmodel: CFModel, config: Config, extras: Optional[Dict] = None) -> Result:
        result = Result()
        for rule in self.rules:
            if rule.rule_mode == RuleMode.DISABLED:
                continue

            try:
                result += rule.invoke(cfmodel, extras)
            except Exception as other_exception:
                result.add_exception(other_exception)
                logger.exception(
                    "{} crashed with {} for project - {}, service - {}, stack - {}".format(
                        type(rule).__name__,
                        type(other_exception).__name__,
                        config.project_name,
                        config.service_name,
                        config.stack_name,
                    )
                )
                continue
        return result

    @staticmethod
    def _annotate_branch(result: Result, branch_path: Tuple[str, ...]) -> None:
        """Make every finding of a branch variant locatable in the template."""
        branch_descriptor = ", ".join(branch_path)
        for failure in result.failures:
            failure.reason = f"{failure.reason} [conditional branch: {branch_descriptor}]"
