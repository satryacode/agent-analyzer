from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, ClassVar, Dict, Optional, Tuple, Union

import yaml
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_VALID_RANGES: Dict[str, Tuple[float, float]] = {
    "confirm_confidence_threshold": (0.0, 1.0),
    "dismiss_confidence_threshold": (0.0, 1.0),
    "poll_interval_seconds": (1, 3600),
    "llm_max_tokens": (64, 4096),
}

_DEFAULTS: Dict[str, Union[int, float]] = {
    "confirm_confidence_threshold": 0.8,
    "dismiss_confidence_threshold": 0.5,
    "poll_interval_seconds": 10,
    "llm_max_tokens": 512,
}


def _load_yaml_config(config_file: Optional[str]) -> Dict[str, Any]:
    if not config_file:
        return {}
    path = Path(config_file)
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, PermissionError) as exc:
        logger.warning("Config file '%s' unreadable (%s). Using defaults.", config_file, exc)
        return {}
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        logger.warning("Config file '%s' malformed (%s). Using defaults.", config_file, exc)
        return {}
    if not isinstance(data, dict):
        logger.warning("Config file '%s' not a YAML mapping. Using defaults.", config_file)
        return {}
    return data


class AnalyzerConfig(BaseSettings):
    """Configuration for the Fraud Verdict Analyzer.

    Precedence (highest to lowest):
    1. Environment variables (ANALYZER_ prefix)
    2. YAML config file values
    3. Default values
    """

    model_config = SettingsConfigDict(
        env_prefix="ANALYZER_",
        env_file=None,
        extra="ignore",
    )

    # Decision thresholds
    confirm_confidence_threshold: float = 0.8
    dismiss_confidence_threshold: float = 0.5

    # AWS Bedrock / Amazon Nova
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "amazon.nova-lite-v1:0"
    llm_max_tokens: int = 512

    # Polling
    poll_interval_seconds: int = 10

    # Report output
    report_file_path: str = "findings.jsonl"

    # Optional YAML config
    config_file: Optional[str] = None

    _valid_ranges: ClassVar[Dict[str, Tuple[float, float]]] = _VALID_RANGES
    _defaults: ClassVar[Dict[str, Union[int, float]]] = _DEFAULTS

    def __init__(self, **kwargs: Any) -> None:
        config_file = kwargs.get("config_file") or os.environ.get("ANALYZER_CONFIG_FILE")
        yaml_values = _load_yaml_config(config_file)
        if yaml_values:
            env_prefix = "ANALYZER_"
            filtered = {
                k: v for k, v in yaml_values.items()
                if (env_prefix + k.upper()) not in os.environ
            }
            merged = {**filtered, **kwargs}
            if config_file and "config_file" not in kwargs:
                merged["config_file"] = config_file
        else:
            merged = kwargs
            if config_file and "config_file" not in kwargs:
                merged["config_file"] = config_file
        super().__init__(**merged)

    @model_validator(mode="after")
    def _validate_ranges(self) -> "AnalyzerConfig":
        for field_name, (min_val, max_val) in _VALID_RANGES.items():
            value = getattr(self, field_name)
            if value < min_val or value > max_val:
                default = _DEFAULTS[field_name]
                logger.warning(
                    "Config value '%s=%s' outside [%s, %s]. Using default %s.",
                    field_name, value, min_val, max_val, default,
                )
                object.__setattr__(self, field_name, default)
        return self
