from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from models import AnalysisDecision, VerdictRecord
from analyzer.base import BaseEvaluator

# Reasons that always confirm regardless of confidence score
_ALWAYS_CONFIRM = frozenset({"sql_injection", "scanner_detected"})

# Reasons considered low-severity — only dismissed when alone and confidence is low
_LOW_SEVERITY = frozenset({"path_enumeration", "unusual_user_agent"})


class RuleEvaluator(BaseEvaluator):
    def __init__(
        self,
        confirm_threshold: float = 0.8,
        dismiss_threshold: float = 0.5,
    ) -> None:
        self._confirm_threshold = confirm_threshold
        self._dismiss_threshold = dismiss_threshold

    def evaluate(self, record: VerdictRecord) -> Optional[AnalysisDecision]:
        reasons = {r.strip() for r in record.reason.split(",") if r.strip()}
        now = datetime.now(tz=timezone.utc).isoformat()

        matched_critical = reasons & _ALWAYS_CONFIRM
        if matched_critical:
            return AnalysisDecision(
                verdict_id=record.id,
                decision="CONFIRM",
                reasoning=f"Critical indicator(s) detected: {', '.join(sorted(matched_critical))}",
                analyzed_at=now,
            )

        if record.confidence_score >= self._confirm_threshold:
            return AnalysisDecision(
                verdict_id=record.id,
                decision="CONFIRM",
                reasoning=f"Confidence {record.confidence_score:.2f} >= threshold {self._confirm_threshold}",
                analyzed_at=now,
            )

        if "brute_force" in reasons and "credential_stuffing" in reasons:
            return AnalysisDecision(
                verdict_id=record.id,
                decision="CONFIRM",
                reasoning="Combined brute_force + credential_stuffing attack pattern",
                analyzed_at=now,
            )

        if record.confidence_score < self._dismiss_threshold and reasons.issubset(_LOW_SEVERITY):
            return AnalysisDecision(
                verdict_id=record.id,
                decision="DISMISS",
                reasoning=(
                    f"Confidence {record.confidence_score:.2f} < {self._dismiss_threshold} "
                    f"with only low-severity indicator(s): {', '.join(sorted(reasons))}"
                ),
                analyzed_at=now,
            )

        # Ambiguous — let LLM decide
        return None
