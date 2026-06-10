from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from models import AnalysisDecision, VerdictRecord


class BaseEvaluator(ABC):
    @abstractmethod
    def evaluate(self, record: VerdictRecord) -> Optional[AnalysisDecision]:
        """Return a decision, or None to pass to the next evaluator."""
