from __future__ import annotations

import logging
import os
from typing import Optional

import psycopg2

from models import AnalysisDecision

logger = logging.getLogger(__name__)

_UPDATE_VERDICT_SQL = "UPDATE fraud_verdicts SET remediated = 1 WHERE id = %s"
_BLOCK_USER_SQL = "UPDATE users SET blocked = 1 WHERE username = %s"


class DBUpdater:
    def __init__(
        self,
        db_host: Optional[str] = None,
        db_port: Optional[int] = None,
        db_name: Optional[str] = None,
        db_user: Optional[str] = None,
        db_pass: Optional[str] = None,
    ):
        self._params = {
            "host": db_host or os.environ.get("DB_HOST", "127.0.0.1"),
            "port": int(db_port or os.environ.get("DB_PORT", 5432)),
            "dbname": db_name or os.environ.get("DB_NAME", "myapp_db"),
            "user": db_user or os.environ.get("DB_USER", "myapp_user"),
            "password": db_pass or os.environ.get("DB_PASS", ""),
        }
        self._conn = None
        self._connect()

    def _connect(self) -> None:
        try:
            self._conn = psycopg2.connect(**self._params)
            logger.info("DBUpdater connected to PostgreSQL at %s", self._params["host"])
        except Exception as exc:
            logger.warning("DBUpdater could not connect: %s — updates disabled", exc)
            self._conn = None

    def apply(self, decision: AnalysisDecision, user_identity: Optional[str]) -> None:
        """Mark verdict as remediated and optionally block the user — atomically."""
        if self._conn is None:
            self._connect()
        if self._conn is None:
            logger.error("DBUpdater: no connection, skipping verdict_id=%d", decision.verdict_id)
            return

        try:
            with self._conn.cursor() as cur:
                cur.execute(_UPDATE_VERDICT_SQL, (decision.verdict_id,))
                if decision.decision == "CONFIRM" and user_identity:
                    cur.execute(_BLOCK_USER_SQL, (user_identity,))
                    logger.info(
                        "User '%s' blocked (verdict_id=%d)", user_identity, decision.verdict_id
                    )
            self._conn.commit()
        except Exception as exc:
            logger.error("DBUpdater failed for verdict_id=%d: %s", decision.verdict_id, exc)
            try:
                self._conn.rollback()
            except Exception:
                pass
            self._conn = None  # force reconnect on next call

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
