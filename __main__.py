import argparse
import logging
import sys


def _setup_logging():
    logging.basicConfig(
        stream=sys.stderr,
        format='{"level":"%(levelname)s","ts":"%(asctime)s","logger":"%(name)s","msg":"%(message)s"}',
        level=logging.INFO,
    )


def main():
    _setup_logging()
    parser = argparse.ArgumentParser(description="Fraud Verdict Analyzer")
    parser.add_argument("--config", help="Path to YAML config file")
    args = parser.parse_args()

    from config.settings import AnalyzerConfig
    config = AnalyzerConfig(config_file=args.config) if args.config else AnalyzerConfig()

    from main import run
    run(config)


if __name__ == "__main__":
    main()
