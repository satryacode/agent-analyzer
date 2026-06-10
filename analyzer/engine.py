from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List

from models import AnalysisDecision, VerdictRecord
from analyzer.base import BaseEvaluator

logger = logging.getLogger(__name__)


class AnalysisEngine:
    def __init__(self, evaluators: List[BaseEvaluator]) -> None:
        self._evaluators = evaluators

    def analyze(self, record: VerdictRecord) -> AnalysisDecision:
        for evaluator in self._evaluators:
            decision = evaluator.evaluate(record)
            if decision is not None:
                logger.info(
                    "verdict_id=%d decision=%s evaluator=%s reasoning=%s",
                    record.id,
                    decision.decision,
                    type(evaluator).__name__,
                    decision.reasoning,
                )
                return decision

        # All evaluators passed — safe fallback
        now = datetime.now(tz=timezone.utc).isoformat()
        logger.warning("No evaluator decided for verdict_id=%d — defaulting CONFIRM", record.id)
        return AnalysisDecision(
            verdict_id=record.id,
            decision="CONFIRM",
            reasoning="No evaluator reached a verdict — safe fallback CONFIRM",
            analyzed_at=now,
        )
