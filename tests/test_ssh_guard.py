"""Tests for SSH guard command execution."""

from __future__ import annotations

import os

import pytest

import ssh_guard
from command_config import CommandLimits, CommandParam, CommandSpec


class FakeCompleted:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, stdout: str, stderr: str = "", returncode: int = 0) -> None:
        """Create a fake completed process result.

        Args:
            stdout (str): Captured stdout content.
            stderr (str): Captured stderr content.
            returncode (int): Process return code.
        """
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_run_command_renders_tokens() -> None:
    """Render command tokens into an SSH command.

    This verifies placeholder substitution and execution flow.
    """
    os.environ["SSH_AUTH_SOCK"] = "test"
    record: dict[str, list[str]] = {}

    def runner(cmd, **_kwargs):
        """Capture the SSH command tokens.

        Args:
            cmd (list[str]): Command tokens.
            **_kwargs: Unused keyword arguments.
        """
        record["cmd"] = cmd
        return FakeCompleted(stdout="ok")

    spec = CommandSpec(
        id="cluster_ls",
        description="List directory contents",
        command=["ls", "-la", "--", "{path}"],
        params=[
            CommandParam(name="path", param_type="path", required=True, allowed="all")
        ],
    )
    result = ssh_guard.run_command(
        spec,
        {"path": "/user/davide.mattioli/u20330/sample"},
        runner=runner,
    )
    assert result.stdout == "ok"
    assert "ls" in record["cmd"]


def test_run_command_requires_agent() -> None:
    """Require an SSH agent when batch mode is enabled.

    This prevents interactive passphrase prompts in the server.
    """
    os.environ.pop("SSH_AUTH_SOCK", None)

    def runner(cmd, **_kwargs):
        """Return a successful fake process result.

        Args:
            cmd (list[str]): Command tokens.
            **_kwargs: Unused keyword arguments.
        """
        return FakeCompleted(stdout="ok")

    spec = CommandSpec(
        id="demo",
        description="Demo",
        command=["echo", "{value}"],
        params=[CommandParam(name="value", param_type="string", required=True)],
    )
    with pytest.raises(ssh_guard.CommandError):
        ssh_guard.run_command(spec, {"value": "hi"}, runner=runner)


def test_run_command_applies_value_map() -> None:
    """Apply value_map translations for allowed values.

    This ensures job identifiers map to safe script paths.
    """
    os.environ["SSH_AUTH_SOCK"] = "test"
    record: dict[str, list[str]] = {}

    def runner(cmd, **_kwargs):
        """Capture the SSH command tokens.

        Args:
            cmd (list[str]): Command tokens.
            **_kwargs: Unused keyword arguments.
        """
        record["cmd"] = cmd
        return FakeCompleted(stdout="ok")

    spec = CommandSpec(
        id="cluster_sbatch",
        description="Submit job",
        command=["sbatch", "{job_id}"],
        params=[
            CommandParam(
                name="job_id",
                param_type="path",
                required=True,
                allowed="all",
                allowed_values=["run_main"],
                value_map={"run_main": "/user/davide.mattioli/u20330/run_main.sh"},
            )
        ],
    )
    ssh_guard.run_command(spec, {"job_id": "run_main"}, runner=runner)
    assert "/user/davide.mattioli/u20330/run_main.sh" in record["cmd"]


def test_run_command_enforces_size_limit() -> None:
    """Reject file operations that exceed size limits.

    This protects against large file reads.
    """
    os.environ["SSH_AUTH_SOCK"] = "test"

    def runner(cmd, **_kwargs):
        """Return a fake stat or command output.

        Args:
            cmd (list[str]): Command tokens.
            **_kwargs: Unused keyword arguments.
        """
        if "stat" in cmd:
            return FakeCompleted(stdout="10")
        return FakeCompleted(stdout="ok")

    spec = CommandSpec(
        id="cluster_cat",
        description="Cat a file",
        command=["cat", "--", "{path}"],
        params=[
            CommandParam(name="path", param_type="path", required=True, allowed="all")
        ],
        limits=CommandLimits(max_bytes=5, size_param="path"),
    )
    with pytest.raises(ssh_guard.CommandError):
        ssh_guard.run_command(
            spec,
            {"path": "/user/davide.mattioli/u20330/large.txt"},
            runner=runner,
        )
