from __future__ import annotations

import logging
import signal
import time

from config.settings import AnalyzerConfig
from ingestion.db_reader import DBReader
from analyzer.engine import AnalysisEngine
from analyzer.rule_evaluator import RuleEvaluator
from analyzer.llm_evaluator import LLMEvaluator
from output.db_updater import DBUpdater
from output.nginx_blocklist import NginxBlocklist
from output.report_writer import ReportWriter

logger = logging.getLogger(__name__)


def run(config: AnalyzerConfig) -> None:
    reader = DBReader()
    updater = DBUpdater()
    nginx = NginxBlocklist()
    reporter = ReportWriter(config.report_file_path)
    engine = AnalysisEngine(
        [
            RuleEvaluator(
                confirm_threshold=config.confirm_confidence_threshold,
                dismiss_threshold=config.dismiss_confidence_threshold,
            ),
            LLMEvaluator(
                region=config.aws_region,
                model_id=config.bedrock_model_id,
                max_tokens=config.llm_max_tokens,
            ),
        ]
    )

    running = True

    def _handle_shutdown(sig, frame):
        nonlocal running
        logger.info("Shutdown signal received — stopping after current batch.")
        running = False

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    logger.info(
        "Analyzer started. Poll interval=%ds confirm>=%.2f dismiss<%.2f model=%s",
        config.poll_interval_seconds,
        config.confirm_confidence_threshold,
        config.dismiss_confidence_threshold,
        config.bedrock_model_id,
    )

    while running:
        records = reader.fetch_pending()
        if records:
            logger.info("Fetched %d pending verdict(s).", len(records))
        for record in records:
            decision = engine.analyze(record)
            updater.apply(decision, record.user_identity)
            nginx.apply(decision, record)
            reporter.write(record, decision)

        time.sleep(config.poll_interval_seconds)

    reader.close()
    updater.close()
    nginx.close()
    reporter.close()
    logger.info("Analyzer stopped.")
