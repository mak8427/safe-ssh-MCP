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


def test_run_command_requires_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Require an SSH agent when batch mode is enabled.

    This prevents interactive passphrase prompts in the server.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for controlled patching.
    """
    os.environ.pop("SSH_AUTH_SOCK", None)
    monkeypatch.setattr(ssh_guard, "_default_ssh_auth_sock", lambda: None)

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


def test_run_command_uses_default_agent_socket(tmp_path) -> None:
    """Use fallback SSH_AUTH_SOCK path when env var is missing.

    This supports service-driven environments where the socket is stable.

    Args:
        tmp_path: Temporary directory fixture for fake runtime socket path.
    """
    os.environ.pop("SSH_AUTH_SOCK", None)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    socket_path = runtime_dir / "ssh-agent.socket"
    socket_path.write_text("", encoding="utf-8")
    os.environ["XDG_RUNTIME_DIR"] = str(runtime_dir)

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
    result = ssh_guard.run_command(spec, {"value": "hi"}, runner=runner)
    assert result.stdout == "ok"
    assert os.environ["SSH_AUTH_SOCK"] == str(socket_path)


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


def test_run_command_cd_returns_normalized_path() -> None:
    """Return a validated path for cd commands.

    This avoids an SSH call and only validates the path.
    """
    os.environ["SSH_AUTH_SOCK"] = "test"

    def runner(cmd, **_kwargs):
        """Fail the test if SSH is invoked.

        Args:
            cmd (list[str]): Command tokens.
            **_kwargs: Unused keyword arguments.
        """
        raise AssertionError(f"unexpected SSH call: {cmd}")

    spec = CommandSpec(
        id="cluster_cd",
        description="Change directory",
        command=["cd", "{path}"],
        params=[
            CommandParam(name="path", param_type="path", required=True, allowed="all")
        ],
    )
    result = ssh_guard.run_command(
        spec,
        {"path": "/user/davide.mattioli/u20330"},
        runner=runner,
    )
    assert result.stdout.strip() == "/user/davide.mattioli/u20330"


def test_run_command_adds_strict_ssh_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Add strict host-key options when strict mode is enabled.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for controlled patching.
    """
    os.environ["SSH_AUTH_SOCK"] = "test"
    record: dict[str, list[str]] = {}
    monkeypatch.setattr(
        ssh_guard.config, "ENFORCE_STRICT_HOST_KEY_CHECKING", True, raising=False
    )
    monkeypatch.setattr(
        ssh_guard.config,
        "SSH_KNOWN_HOSTS_FILE",
        "/home/mak/.ssh/known_hosts",
        raising=False,
    )

    def runner(cmd, **_kwargs):
        """Capture command tokens.

        Args:
            cmd (list[str]): Command tokens.
            **_kwargs: Unused keyword arguments.
        """
        record["cmd"] = cmd
        return FakeCompleted(stdout="ok")

    spec = CommandSpec(
        id="demo",
        description="Demo",
        command=["echo", "{value}"],
        params=[CommandParam(name="value", param_type="string", required=True)],
    )
    result = ssh_guard.run_command(spec, {"value": "hi"}, runner=runner)
    assert result.stdout == "ok"
    joined = " ".join(record["cmd"])
    assert "StrictHostKeyChecking=yes" in joined
    assert "UserKnownHostsFile=/home/mak/.ssh/known_hosts" in joined
    assert "IdentitiesOnly=yes" in joined


def test_run_command_rejects_canonical_path_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a path that resolves outside the allow-list in strict mode.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for controlled patching.
    """
    os.environ["SSH_AUTH_SOCK"] = "test"
    monkeypatch.setattr(
        ssh_guard.config, "ENFORCE_CANONICAL_PATH_CHECKS", True, raising=False
    )

    def runner(cmd, **_kwargs):
        """Return canonical path escape output for readlink.

        Args:
            cmd (list[str]): Command tokens.
            **_kwargs: Unused keyword arguments.
        """
        if "readlink" in cmd:
            return FakeCompleted(stdout="/etc/passwd\n")
        return FakeCompleted(stdout="ok")

    spec = CommandSpec(
        id="cluster_ls",
        description="List",
        command=["ls", "-la", "--", "{path}"],
        params=[
            CommandParam(name="path", param_type="path", required=True, allowed="all")
        ],
    )
    with pytest.raises(ssh_guard.CommandError):
        ssh_guard.run_command(
            spec,
            {"path": "/user/davide.mattioli/u20330/symlink"},
            runner=runner,
        )


def test_run_command_requires_known_hosts_for_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Require known_hosts path when strict host checking is enabled.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for controlled patching.
    """
    os.environ["SSH_AUTH_SOCK"] = "test"
    monkeypatch.setattr(
        ssh_guard.config, "ENFORCE_STRICT_HOST_KEY_CHECKING", True, raising=False
    )
    monkeypatch.setattr(ssh_guard.config, "SSH_KNOWN_HOSTS_FILE", "", raising=False)
    spec = CommandSpec(
        id="demo",
        description="Demo",
        command=["echo", "{value}"],
        params=[CommandParam(name="value", param_type="string", required=True)],
    )
    with pytest.raises((ValueError, ssh_guard.CommandError)):
        ssh_guard.run_command(spec, {"value": "hi"}, runner=lambda *_a, **_k: None)
