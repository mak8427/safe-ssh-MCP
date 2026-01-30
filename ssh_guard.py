"""Guarded SSH command execution with strict allow-lists."""

from __future__ import annotations

import posixpath
import subprocess
from dataclasses import dataclass
from pathlib import PurePosixPath

import config


class CommandError(ValueError):
    """Raised when a command violates guard rules."""


@dataclass
class CommandResult:
    """Captured stdout/stderr and exit code from SSH command."""

    stdout: str
    stderr: str
    exit_code: int


def _normalize_remote_path(path: str) -> str:
    if not isinstance(path, str) or not path.strip():
        raise CommandError("path must be a non-empty string")
    if "\x00" in path or "\n" in path or "\r" in path:
        raise CommandError("path contains invalid characters")
    if path.startswith("~"):
        raise CommandError("tilde expansion is not allowed")
    norm = posixpath.normpath(path)
    if not norm.startswith("/"):
        raise CommandError("path must be absolute")

    base = config.BASE_PATH.rstrip("/")
    if norm == base or norm.startswith(base + "/"):
        return norm
    raise CommandError("path is outside allowed base directory")


def _validate_token(token: str, name: str) -> None:
    if not isinstance(token, str) or token == "":
        raise CommandError(f"{name} must be a non-empty string")
    if "\x00" in token or "\n" in token or "\r" in token:
        raise CommandError(f"{name} contains invalid characters")


def _run_ssh(cmd: list[str]) -> CommandResult:
    for i, item in enumerate(cmd):
        _validate_token(item, f"arg[{i}]")

    ssh_cmd = ["ssh"]
    if getattr(config, "SSH_BATCH_MODE", False):
        ssh_cmd.extend(["-o", "BatchMode=yes"])
    connect_timeout = getattr(config, "SSH_CONNECT_TIMEOUT", None)
    if connect_timeout:
        ssh_cmd.extend(["-o", f"ConnectTimeout={int(connect_timeout)}"])
    ssh_cmd.extend(
        [
            "-i",
            config.SSH_KEY,
            f"{config.SSH_USER}@{config.SSH_HOST}",
            *cmd,
        ]
    )
    completed = subprocess.run(
        ssh_cmd,
        capture_output=True,
        text=True,
        timeout=config.SSH_TIMEOUT,
        check=False,
    )
    return CommandResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
    )


def squeue() -> CommandResult:
    """Run squeue for the current user."""
    return _run_ssh(["squeue", "--me"])


def sacct() -> CommandResult:
    """Run sacct with a fixed safe flag set."""
    return _run_ssh(["sacct", "-u", config.SSH_USER, "-X", "-n", "-P"])


def ls(path: str) -> CommandResult:
    """List directory contents at path."""
    norm = _normalize_remote_path(path)
    return _run_ssh(["ls", "-la", "--", norm])


def stat(path: str) -> CommandResult:
    """Show stat info for a path."""
    norm = _normalize_remote_path(path)
    return _run_ssh(["stat", "--", norm])


def head(path: str, n: int) -> CommandResult:
    """Show the first N lines of a file."""
    norm = _normalize_remote_path(path)
    if not (1 <= n <= config.MAX_HEAD_TAIL_LINES):
        raise CommandError("n is outside allowed range")
    return _run_ssh(["head", "-n", str(n), "--", norm])


def tail(path: str, n: int) -> CommandResult:
    """Show the last N lines of a file."""
    norm = _normalize_remote_path(path)
    if not (1 <= n <= config.MAX_HEAD_TAIL_LINES):
        raise CommandError("n is outside allowed range")
    return _run_ssh(["tail", "-n", str(n), "--", norm])


def _remote_file_size(path: str) -> int:
    norm = _normalize_remote_path(path)
    result = _run_ssh(["stat", "-c", "%s", "--", norm])
    if result.exit_code != 0:
        raise CommandError(result.stderr.strip() or "stat failed")
    try:
        return int(result.stdout.strip())
    except ValueError as exc:
        raise CommandError("stat returned non-numeric size") from exc


def cat(path: str) -> CommandResult:
    """Cat a file with a size guard."""
    norm = _normalize_remote_path(path)
    size = _remote_file_size(norm)
    if size > config.MAX_CAT_BYTES:
        raise CommandError("file is too large to cat safely")
    return _run_ssh(["cat", "--", norm])


def grep(pattern: str, path: str) -> CommandResult:
    """Run grep (recursive) with match limit."""
    _validate_token(pattern, "pattern")
    if len(pattern) > config.MAX_GREP_PATTERN_LEN:
        raise CommandError("pattern is too long")
    norm = _normalize_remote_path(path)
    return _run_ssh(
        [
            "grep",
            "-R",
            "-n",
            "-m",
            str(config.MAX_GREP_MATCHES),
            "--binary-files=without-match",
            "--",
            pattern,
            norm,
        ]
    )


def sbatch(job_id: str) -> CommandResult:
    """Submit a whitelisted sbatch script by id."""
    _validate_token(job_id, "job_id")
    script_path = config.SBATCH_SCRIPTS.get(job_id)

    if not script_path:
        raise CommandError("job_id is not in the allow-list")

    norm = _normalize_remote_path(script_path)
    return _run_ssh(["sbatch", norm])
