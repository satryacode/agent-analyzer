from __future__ import annotations

import json
import logging
from typing import Optional

from models import AnalysisDecision, FindingReport, VerdictRecord

logger = logging.getLogger(__name__)


class ReportWriter:
    def __init__(self, file_path: str = "findings.jsonl") -> None:
        self._file_path = file_path
        try:
            self._file = open(file_path, "a", encoding="utf-8")
            logger.info("ReportWriter appending to %s", file_path)
        except OSError as exc:
            logger.warning("ReportWriter could not open %s: %s — file output disabled", file_path, exc)
            self._file = None

    def write(self, record: VerdictRecord, decision: AnalysisDecision) -> None:
        if decision.decision == "CONFIRM":
            action = "user_blocked" if record.user_identity else "flagged_no_user"
        else:
            action = "dismissed"

        finding = FindingReport(
            verdict_id=record.id,
            source_ip=record.source_ip,
            user_identity=record.user_identity,
            reason=record.reason,
            confidence_score=record.confidence_score,
            action_taken=action,
            analyzed_at=decision.analyzed_at,
        )
        line = json.dumps(
            {
                "verdict_id": finding.verdict_id,
                "source_ip": finding.source_ip,
                "user_identity": finding.user_identity,
                "reason": finding.reason,
                "confidence_score": finding.confidence_score,
                "action_taken": finding.action_taken,
                "analyzed_at": finding.analyzed_at,
                "reasoning": decision.reasoning,
            },
            ensure_ascii=False,
        )

        print(line)

        if self._file is not None:
            try:
                self._file.write(line + "\n")
                self._file.flush()
            except OSError as exc:
                logger.error("ReportWriter write failed: %s", exc)

    def close(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None
