from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from models import AnalysisDecision, VerdictRecord
from analyzer.base import BaseEvaluator
from ingestion.ip_reputation import IpReputation

# Reasons that always confirm regardless of confidence score.
_ALWAYS_CONFIRM = frozenset({"sql_injection", "scanner_detected"})

# Hard attack reasons that justify a network-layer IP block on confirm.
_HIGH_SEVERITY = frozenset({
    "sql_injection", "scanner_detected", "brute_force", "credential_stuffing",
})

# Reasons considered low-severity — only dismissed when alone and confidence is low.
_LOW_SEVERITY = frozenset({"path_enumeration", "unusual_user_agent"})


class RuleEvaluator(BaseEvaluator):
    def __init__(
        self,
        confirm_threshold: float = 0.8,
        dismiss_threshold: float = 0.5,
        reputation: Optional[IpReputation] = None,
        repeat_offender_threshold: int = 5,
    ) -> None:
        self._confirm_threshold = confirm_threshold
        self._dismiss_threshold = dismiss_threshold
        self._reputation = reputation
        # Number of prior verdicts in the window that flips an otherwise
        # low-signal, repeated probe (recon / path enumeration) into a block.
        self._repeat_offender_threshold = repeat_offender_threshold

    def evaluate(self, record: VerdictRecord) -> Optional[AnalysisDecision]:
        reasons = {r.strip() for r in record.reason.split(",") if r.strip()}
        now = datetime.now(tz=timezone.utc).isoformat()
        high_sev = bool(reasons & _HIGH_SEVERITY)

        def confirm(reasoning: str, enforce: bool) -> AnalysisDecision:
            return AnalysisDecision(
                verdict_id=record.id,
                decision="CONFIRM",
                reasoning=reasoning,
                analyzed_at=now,
                enforce_ip_block=enforce,
            )

        # 1. Critical indicators — confirm and hard-block regardless of confidence.
        matched_critical = reasons & _ALWAYS_CONFIRM
        if matched_critical:
            return confirm(
                f"Critical indicator(s) detected: {', '.join(sorted(matched_critical))}",
                enforce=True,
            )

        # 2. brute_force or credential_stuffing alone is a hard attack — don't
        #    defer single-indicator brute force to the lenient LLM.
        if "brute_force" in reasons or "credential_stuffing" in reasons:
            return confirm(
                f"Hard attack indicator(s): {', '.join(sorted(reasons & _HIGH_SEVERITY))}",
                enforce=True,
            )

        # 3. High raw confidence — confirm. IP-block only if a hard reason is present.
        if record.confidence_score >= self._confirm_threshold:
            return confirm(
                f"Confidence {record.confidence_score:.2f} >= threshold {self._confirm_threshold}",
                enforce=high_sev,
            )

        # 4. Reputation escalation — a repeat offender doing the same low-signal
        #    probing over and over (recon, path enumeration) gets blocked by volume.
        rep = self._reputation.lookup(record.source_ip) if self._reputation else None
        if rep is not None and (
            rep.already_blocked or rep.total_verdicts >= self._repeat_offender_threshold
        ):
            return confirm(f"Repeat offender — {rep.summary_line()}", enforce=True)

        # 5. Lone low-severity probe at low confidence — dismiss.
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

        # Ambiguous — let the LLM decide (with reputation context).
        return None
