from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
from typing import Optional

import psycopg2

from models import AnalysisDecision, VerdictRecord

logger = logging.getLogger(__name__)

_BLOCKED_IPS_PATH = os.environ.get("NGINX_BLOCKED_IPS_PATH", "/etc/nginx/blocked_ips.conf")

_INSERT_SQL = """
    INSERT INTO blocked_ips (source_ip, verdict_id, reason)
    VALUES (%s, %s, %s)
    ON CONFLICT (source_ip) DO NOTHING
"""


class NginxBlocklist:
    def __init__(
        self,
        db_host: Optional[str] = None,
        db_port: Optional[int] = None,
        db_name: Optional[str] = None,
        db_user: Optional[str] = None,
        db_pass: Optional[str] = None,
        blocked_ips_path: str = _BLOCKED_IPS_PATH,
    ) -> None:
        self._path = blocked_ips_path
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
            logger.info("NginxBlocklist connected to PostgreSQL at %s", self._params["host"])
        except Exception as exc:
            logger.warning("NginxBlocklist could not connect to DB: %s", exc)
            self._conn = None

    def apply(self, decision: AnalysisDecision, record: VerdictRecord) -> None:
        # Policy lives in the evaluator: it decides whether a confirmation
        # warrants a hard network-layer block (enforce_ip_block). The IP block
        # and any user block are independent — an attacker supplying a username
        # (even a SQL-injection payload as the username) must not escape the ban.
        if decision.decision != "CONFIRM" or not decision.enforce_ip_block:
            return

        try:
            addr = ipaddress.ip_address(record.source_ip)
            if addr.is_loopback or addr.is_private:
                logger.info("NginxBlocklist: skipping IP block for %s — loopback/private", record.source_ip)
                return
        except ValueError:
            pass

        self._insert_db(record)
        self._write_nginx_deny(record.source_ip)
        self._reload_nginx()

    def _insert_db(self, record: VerdictRecord) -> None:
        if self._conn is None:
            self._connect()
        if self._conn is None:
            logger.error("NginxBlocklist: no DB connection, skipping insert for %s", record.source_ip)
            return
        try:
            with self._conn.cursor() as cur:
                cur.execute(_INSERT_SQL, (record.source_ip, record.id, record.reason))
            self._conn.commit()
            logger.info("NginxBlocklist: recorded IP %s (verdict_id=%d)", record.source_ip, record.id)
        except Exception as exc:
            logger.error("NginxBlocklist DB insert failed for %s: %s", record.source_ip, exc)
            try:
                self._conn.rollback()
            except Exception:
                pass
            self._conn = None

    def _write_nginx_deny(self, ip: str) -> None:
        try:
            # Read current deny rules to avoid duplicates
            existing: set[str] = set()
            try:
                with open(self._path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("deny "):
                            existing.add(line.removeprefix("deny ").rstrip(";"))
            except FileNotFoundError:
                pass

            if ip in existing:
                return

            with open(self._path, "a") as f:
                f.write(f"deny {ip};\n")
            logger.info("NginxBlocklist: added deny rule for %s", ip)
        except OSError as exc:
            logger.error("NginxBlocklist: could not write %s: %s", self._path, exc)

    def _reload_nginx(self) -> None:
        try:
            result = subprocess.run(
                ["sudo", "nginx", "-s", "reload"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                logger.info("NginxBlocklist: nginx reloaded")
            else:
                logger.error("NginxBlocklist: nginx reload failed: %s", result.stderr.strip())
        except Exception as exc:
            logger.error("NginxBlocklist: nginx reload error: %s", exc)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
