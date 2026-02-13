"""Tests for command configuration parsing and validation."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

import command_config


def test_parse_yaml_basic() -> None:
    """Validate basic YAML parsing with a command entry.

    This covers the minimal configuration structure.
    """
    data = command_config.parse_yaml(textwrap.dedent("""\
            version: 1
            commands:
              - id: demo
                description: Demo command
                command:
                  - echo
                  - "{ssh_user}"
            """))
    assert data["version"] == 1
    assert data["commands"][0]["id"] == "demo"


def test_load_command_config_valid(tmp_path: Path) -> None:
    """Load a valid command config from disk.

    Args:
        tmp_path (Path): Temporary directory for the config file.
    """
    config_path = tmp_path / "commands.yml"
    config_path.write_text(
        textwrap.dedent("""\
            version: 1
            commands:
              - id: demo
                description: Demo command
                command:
                  - echo
                  - "{ssh_user}"
                params:
                  path:
                    type: path
                    required: true
                    allowed: all
            """),
        encoding="utf-8",
    )
    specs = command_config.load_command_config(config_path)
    assert specs[0].id == "demo"
    assert specs[0].params[0].name == "path"


def test_load_command_config_rejects_unknown_placeholders(tmp_path: Path) -> None:
    """Reject unknown placeholders in command tokens.

    Args:
        tmp_path (Path): Temporary directory for the config file.
    """
    config_path = tmp_path / "commands.yml"
    config_path.write_text(
        textwrap.dedent("""\
            version: 1
            commands:
              - id: demo
                description: Demo command
                command:
                  - echo
                  - "{missing}"
            """),
        encoding="utf-8",
    )
    with pytest.raises(command_config.CommandConfigError):
        command_config.load_command_config(config_path)


def test_load_command_config_rejects_value_map_mismatch(tmp_path: Path) -> None:
    """Reject value_map mismatch with allowed_values.

    Args:
        tmp_path (Path): Temporary directory for the config file.
    """
    config_path = tmp_path / "commands.yml"
    config_path.write_text(
        textwrap.dedent("""\
            version: 1
            commands:
              - id: demo
                description: Demo command
                command:
                  - echo
                  - "{job_id}"
                params:
                  job_id:
                    type: string
                    required: true
                    allowed_values:
                      - one
                    value_map:
                      two: /tmp/other
            """),
        encoding="utf-8",
    )
    with pytest.raises(command_config.CommandConfigError):
        command_config.load_command_config(config_path)


def test_parse_yaml_warns_on_duplicate_key_in_compat_mode(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Warn and keep last value when duplicate keys are allowed.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for controlled patching.
        caplog (pytest.LogCaptureFixture): Fixture for log assertions.
    """
    monkeypatch.setattr(
        command_config.config, "REJECT_DUPLICATE_YAML_KEYS", False, raising=False
    )
    caplog.set_level("WARNING", logger="cluster_tools")
    data = command_config.parse_yaml(textwrap.dedent("""\
            version: 1
            version: 2
            commands: []
            """))
    assert data["version"] == 2
    assert "duplicate key 'version'" in caplog.text


def test_parse_yaml_rejects_duplicate_key_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject duplicate keys when strict parsing mode is enabled.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for controlled patching.
    """
    monkeypatch.setattr(
        command_config.config, "REJECT_DUPLICATE_YAML_KEYS", True, raising=False
    )
    with pytest.raises(command_config.CommandConfigError):
        command_config.parse_yaml(textwrap.dedent("""\
                version: 1
                version: 2
                commands: []
                """))


def test_load_command_config_rejects_non_positive_max_bytes(tmp_path: Path) -> None:
    """Reject non-positive max_bytes in command limits.

    Args:
        tmp_path (Path): Temporary directory for the config file.
    """
    config_path = tmp_path / "commands.yml"
    config_path.write_text(
        textwrap.dedent("""\
            version: 1
            commands:
              - id: demo
                description: Demo command
                command:
                  - cat
                  - "{path}"
                params:
                  path:
                    type: path
                    required: true
                    allowed: all
                limits:
                  max_bytes: 0
                  size_param: path
            """),
        encoding="utf-8",
    )
    with pytest.raises(command_config.CommandConfigError):
        command_config.load_command_config(config_path)
