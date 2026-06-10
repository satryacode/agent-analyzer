from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import List, Optional

import psycopg2

from models import VerdictRecord

logger = logging.getLogger(__name__)

_SELECT_SQL = """
    SELECT id, source_ip, user_identity, method, path,
           confidence_score, reason, original_log_entry_reference, detected_at
    FROM fraud_verdicts
    WHERE remediated = 0
    ORDER BY detected_at ASC
"""


class DBReader:
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
            logger.info("DBReader connected to PostgreSQL at %s", self._params["host"])
        except Exception as exc:
            logger.warning("DBReader could not connect: %s — reads disabled", exc)
            self._conn = None

    def fetch_pending(self) -> List[VerdictRecord]:
        if self._conn is None:
            self._connect()
        if self._conn is None:
            return []
        try:
            with self._conn.cursor() as cur:
                cur.execute(_SELECT_SQL)
                rows = cur.fetchall()
            return [_row_to_record(row) for row in rows]
        except Exception as exc:
            logger.error("DBReader fetch failed: %s", exc)
            try:
                self._conn.rollback()
            except Exception:
                pass
            self._conn = None
            return []

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None


def _row_to_record(row) -> VerdictRecord:
    detected_at = row[8]
    if not isinstance(detected_at, datetime):
        detected_at = datetime.fromisoformat(str(detected_at))
    return VerdictRecord(
        id=row[0],
        source_ip=row[1],
        user_identity=row[2],
        method=row[3],
        path=row[4],
        confidence_score=float(row[5]),
        reason=row[6] or "",
        original_log_entry_reference=row[7] or "",
        detected_at=detected_at,
    )
