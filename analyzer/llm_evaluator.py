from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from models import AnalysisDecision, VerdictRecord
from analyzer.base import BaseEvaluator
from ingestion.ip_reputation import IpReputation

logger = logging.getLogger(__name__)

# Hard attack reasons that justify a network-layer IP block on confirm.
_HIGH_SEVERITY = frozenset({
    "sql_injection", "scanner_detected", "brute_force", "credential_stuffing",
})

_SYSTEM_PROMPT = (
    "You are a security analyst reviewing fraud verdicts from an automated classifier. "
    "Your task: CONFIRM (real attack — block the user) or DISMISS (false positive — leave unblocked). "
    "Weigh the source IP's recent history heavily: a single 404 may look benign, but the same IP "
    "probing many endpoints in a short window is reconnaissance and should be CONFIRMED. "
    "Respond with a JSON object only, no other text:\n"
    '{"decision": "CONFIRM" or "DISMISS", "reasoning": "one sentence"}'
)

_USER_PROMPT_TEMPLATE = """\
Verdict to review:
- Source IP: {source_ip}
- User identity: {user_identity}
- HTTP method: {method}
- Path: {path}
- Confidence score: {confidence_score:.2f}
- Classifier reasons: {reason}
- Source IP recent history: {reputation}
- Original request log: {original_log}

Should this verdict be CONFIRMED (block user) or DISMISSED (false positive)?"""


class LLMEvaluator(BaseEvaluator):
    def __init__(
        self,
        region: str = "us-east-1",
        model_id: str = "amazon.nova-lite-v1:0",
        max_tokens: int = 512,
        reputation: Optional[IpReputation] = None,
    ) -> None:
        self._model_id = model_id
        self._max_tokens = max_tokens
        self._reputation = reputation
        try:
            self._client = boto3.client("bedrock-runtime", region_name=region)
            logger.info("LLMEvaluator ready: model=%s region=%s", model_id, region)
        except Exception as exc:
            logger.warning("LLMEvaluator Bedrock init failed: %s — LLM disabled", exc)
            self._client = None

    def evaluate(self, record: VerdictRecord) -> Optional[AnalysisDecision]:
        reasons = {r.strip() for r in record.reason.split(",") if r.strip()}
        rep = self._reputation.lookup(record.source_ip) if self._reputation else None
        # A confirmed verdict warrants a hard IP block when a hard attack reason
        # is present, or the IP is a known repeat offender.
        enforce = bool(reasons & _HIGH_SEVERITY) or (rep.is_repeat_offender if rep else False)
        rep_text = rep.summary_line() if rep else "no history available"

        if self._client is None:
            return self._fallback(record.id, "Bedrock client unavailable", enforce)

        prompt = _USER_PROMPT_TEMPLATE.format(
            source_ip=record.source_ip,
            user_identity=record.user_identity or "unknown",
            method=record.method,
            path=record.path,
            confidence_score=record.confidence_score,
            reason=record.reason,
            reputation=rep_text,
            original_log=record.original_log_entry_reference[:500],
        )

        try:
            response = self._client.converse(
                modelId=self._model_id,
                system=[{"text": _SYSTEM_PROMPT}],
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={"maxTokens": self._max_tokens, "temperature": 0.1},
            )
            text = response["output"]["message"]["content"][0]["text"].strip()
            logger.debug("LLMEvaluator raw response: %r", text[:300])
            return self._parse_response(record.id, text, enforce)
        except (BotoCoreError, ClientError) as exc:
            logger.error("LLMEvaluator Bedrock call failed for verdict_id=%d: %s", record.id, exc)
            return self._fallback(record.id, f"Bedrock error: {exc}", enforce)
        except Exception as exc:
            logger.error("LLMEvaluator unexpected error for verdict_id=%d: %s", record.id, exc)
            return self._fallback(record.id, f"Unexpected error: {exc}", enforce)

    def _parse_response(self, verdict_id: int, text: str, enforce: bool) -> AnalysisDecision:
        now = datetime.now(tz=timezone.utc).isoformat()
        try:
            clean = text.strip()
            # Strip markdown code fences if present
            if clean.startswith("```"):
                lines = clean.splitlines()
                inner = [l for l in lines[1:] if l.strip() != "```"]
                clean = "\n".join(inner)
            data = json.loads(clean)
            decision = str(data.get("decision", "")).upper()
            if decision not in ("CONFIRM", "DISMISS"):
                raise ValueError(f"unexpected decision value: {decision!r}")
            reasoning = str(data.get("reasoning", "LLM analysis"))
            return AnalysisDecision(
                verdict_id=verdict_id,
                decision=decision,
                reasoning=f"[LLM] {reasoning}",
                analyzed_at=now,
                enforce_ip_block=enforce if decision == "CONFIRM" else False,
            )
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning(
                "LLMEvaluator parse error (%s) for verdict_id=%d — defaulting CONFIRM. Response: %r",
                exc, verdict_id, text[:200],
            )
            return AnalysisDecision(
                verdict_id=verdict_id,
                decision="CONFIRM",
                reasoning=f"[LLM fallback] Parse error ({exc}) — defaulting to CONFIRM",
                analyzed_at=now,
                enforce_ip_block=enforce,
            )

    def _fallback(self, verdict_id: int, reason: str, enforce: bool = False) -> AnalysisDecision:
        now = datetime.now(tz=timezone.utc).isoformat()
        return AnalysisDecision(
            verdict_id=verdict_id,
            decision="CONFIRM",
            reasoning=f"[LLM fallback] {reason} — defaulting to CONFIRM",
            analyzed_at=now,
            enforce_ip_block=enforce,
        )
