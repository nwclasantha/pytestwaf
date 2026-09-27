"""Tests for config module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from gotestwaf.config.config import Config, load_config_from_yaml


class TestConfig:
    def test_default_values(self) -> None:
        cfg = Config()
        assert cfg.url == ""
        assert cfg.workers == 5
        assert cfg.block_status_codes == [403]
        assert cfg.pass_status_codes == [200, 404]
        assert cfg.http_client == "gohttp"
        assert cfg.waf_name == "generic"
        assert cfg.send_delay == 400
        assert cfg.random_delay == 400

    def test_mutable_defaults_independent(self) -> None:
        """Each Config instance should have independent mutable fields."""
        cfg1 = Config()
        cfg2 = Config()
        cfg1.block_status_codes.append(503)
        assert 503 not in cfg2.block_status_codes

    def test_check_block_func_is_none(self) -> None:
        cfg = Config()
        assert cfg.check_block_func is None

    def test_args_default_empty(self) -> None:
        cfg = Config()
        assert cfg.args == []


class TestLoadConfigFromYaml:
    def test_load_existing_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("headers:\n  Connection: close\n  User-Agent: test\n")
        result = load_config_from_yaml(str(config_file))
        assert "headers" in result
        assert result["headers"]["Connection"] == "close"

    def test_load_missing_file(self) -> None:
        result = load_config_from_yaml("/nonexistent/path.yaml")
        assert result == {}

    def test_load_empty_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        result = load_config_from_yaml(str(config_file))
        assert result == {}

    def test_load_real_config(self) -> None:
        """Load the actual project config.yaml."""
        result = load_config_from_yaml("config.yaml")
        if result:  # File may not exist in CI
            assert "headers" in result
