from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class VerdictRecord:
    id: int
    source_ip: str
    user_identity: Optional[str]
    method: str
    path: str
    confidence_score: float
    reason: str  # comma-separated
    original_log_entry_reference: str
    detected_at: datetime


@dataclass
class AnalysisDecision:
    verdict_id: int
    decision: str  # "CONFIRM" or "DISMISS"
    reasoning: str
    analyzed_at: str
    # Whether this confirmation warrants a hard network-layer IP block.
    # The evaluator (policy) decides; NginxBlocklist (actuator) just obeys.
    enforce_ip_block: bool = False


@dataclass
class FindingReport:
    verdict_id: int
    source_ip: str
    user_identity: Optional[str]
    reason: str
    confidence_score: float
    action_taken: str  # "user_blocked" | "flagged_no_user" | "dismissed"
    analyzed_at: str
