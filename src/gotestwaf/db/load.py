"""Test case loading from YAML files.

Uses PyYAML (yaml.safe_load) for YAML 1.1 compatibility, matching Go's
gopkg.in/yaml.v2 behavior. ruamel.yaml uses YAML 1.2 which rejects
escape sequences that Go's parser accepts (e.g. \\' in double-quoted scalars).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from gotestwaf.config.config import Config
from gotestwaf.db.models import Case, Placeholder
from gotestwaf.errors import ConfigError
from gotestwaf.payload.placeholder.placeholder import get_placeholder_config


def load_test_cases(cfg: Config) -> list[Case]:
    """Load test cases from YAML files in the configured test cases path.

    Args:
        cfg: Application configuration.

    Returns:
        List of loaded test cases.

    Raises:
        ConfigError: If no test cases are found or path is empty.
    """
    if not cfg.test_cases_path:
        msg = "empty test cases path"
        raise ConfigError(msg)

    test_cases_path = Path(cfg.test_cases_path)
    test_cases: list[Case] = []

    for yaml_file in sorted(test_cases_path.rglob("*.y*ml")):
        if yaml_file.suffix not in (".yml", ".yaml"):
            continue

        # Extract test set name and test case name from path:
        # .../<testSetName>/<testCaseName>.yml
        parts = yaml_file.parts
        if len(parts) < 3:
            continue

        test_set_name = parts[-2]
        test_case_name = yaml_file.stem

        # Payload pack filtering
        if cfg.payload_pack and cfg.payload_pack != "all":
            PACK_DIRS = {
                "owasp": {"owasp", "owasp-api"},
                "community": {"community"},
                "healthcare": {"healthcare"},
                "finance": {"finance"},
                "government": {"government"},
            }
            allowed = PACK_DIRS.get(cfg.payload_pack)
            if allowed and test_set_name not in allowed and test_set_name != "false-pos":
                continue

        if cfg.test_set and test_set_name != cfg.test_set:
            continue
        if cfg.test_case and test_case_name != cfg.test_case:
            continue

        with yaml_file.open(encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                # Log warning but skip broken YAML files (matches Go behavior)
                import structlog
                structlog.get_logger().warning("skipping YAML file", file=str(yaml_file), error=str(e))
                continue

        if data is None:
            continue

        # Coalesce explicit YAML `null` to empty list — otherwise the
        # scanner's `for payload in ...` loop crashes with TypeError.
        raw_payloads: list[str] = data.get("payload") or []
        raw_encoders: list[str] = data.get("encoder") or []
        raw_placeholders: list[object] = data.get("placeholder") or []
        test_type: str = data.get("type") or "unknown"

        placeholders: list[Placeholder] = []
        for ph in raw_placeholders:
            if isinstance(ph, str):
                placeholders.append(Placeholder(name=ph))
            elif isinstance(ph, dict):
                # dict with single key: placeholder name -> config
                for ph_name, ph_conf in ph.items():
                    ph_config = get_placeholder_config(str(ph_name), ph_conf if isinstance(ph_conf, dict) else {})
                    placeholders.append(Placeholder(name=str(ph_name), config=ph_config))
            else:
                msg = f"couldn't parse config: unknown placeholder type, expected string or dict, got {type(ph).__name__}"
                raise ConfigError(msg)

        test_case = Case(
            payloads=raw_payloads,
            encoders=raw_encoders,
            placeholders=placeholders,
            type=test_type,
            set=test_set_name,
            name=test_case_name,
            is_true_positive="false" not in test_set_name,
        )

        test_cases.append(test_case)

    if not test_cases:
        msg = "no tests were selected"
        raise ConfigError(msg)

    return test_cases
