"""Guarded SSH command execution with strict allow-lists."""

from __future__ import annotations

import logging
import os
import posixpath
import string
import subprocess
from dataclasses import dataclass
from typing import Any, Callable

import config
from command_config import CommandParam, CommandSpec


class CommandError(ValueError):
    """Raised when a command violates guard rules.

    Examples:
        >>> isinstance(CommandError("boom"), ValueError)
        True
    """


@dataclass
class CommandResult:
    """Captured stdout/stderr and exit code from SSH command.

    Examples:
        >>> CommandResult(stdout="ok", stderr="", exit_code=0).exit_code
        0
    """

    stdout: str
    stderr: str
    exit_code: int


def _setup_logging() -> logging.Logger:
    """Configure the module logger.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("cluster_tools")
    if logger.handlers:
        return logger
    level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)
    handler = logging.FileHandler(config.LOG_PATH, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOGGER = _setup_logging()


def _normalize_remote_path(path: str, allowed_prefixes: list[str] | None = None) -> str:
    """Normalize and validate a remote path.

    Args:
        path (str): Remote path to validate.
        allowed_prefixes (list[str] | None): Allowed path prefixes.

    Returns:
        str: Normalized, validated path.
    """
    if not isinstance(path, str) or not path.strip():
        raise CommandError("path must be a non-empty string")
    if "\x00" in path or "\n" in path or "\r" in path:
        raise CommandError("path contains invalid characters")
    if path.startswith("~"):
        raise CommandError("tilde expansion is not allowed")
    norm = posixpath.normpath(path)
    if not norm.startswith("/"):
        raise CommandError("path must be absolute")

    prefixes = allowed_prefixes or config.ALLOWED_PATH_PREFIXES
    if not prefixes:
        raise CommandError("allowed path prefixes are not configured")
    for prefix in prefixes:
        if not isinstance(prefix, str):
            raise CommandError("allowed path prefix must be a string")
        normalized_prefix = posixpath.normpath(prefix)
        if not normalized_prefix.startswith("/"):
            raise CommandError("allowed path prefix must be absolute")
        if norm == normalized_prefix or norm.startswith(normalized_prefix + "/"):
            return norm
    raise CommandError("path is outside allowed base directory")


def _validate_token(token: str, name: str) -> None:
    """Validate a command token.

    Args:
        token (str): Token value to validate.
        name (str): Token label for error messages.
    """
    if not isinstance(token, str) or token == "":
        raise CommandError(f"{name} must be a non-empty string")
    if "\x00" in token or "\n" in token or "\r" in token:
        raise CommandError(f"{name} contains invalid characters")


def _require_ssh_agent() -> None:
    """Ensure an SSH agent is available for batch mode.

    Raises:
        CommandError: If SSH agent is required but unavailable.
    """
    if not getattr(config, "SSH_BATCH_MODE", False):
        return
    if os.environ.get("SSH_AUTH_SOCK"):
        return
    raise CommandError("SSH agent is required when SSH_BATCH_MODE is enabled")


def _run_ssh(
    cmd: list[str],
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Run an SSH command and capture output.

    Args:
        cmd (list[str]): SSH command tokens.
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Returns:
        CommandResult: Captured stdout, stderr, and exit code.
    """
    _require_ssh_agent()
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
    LOGGER.info("run: %s", " ".join(cmd))
    completed = runner(
        ssh_cmd,
        capture_output=True,
        text=True,
        timeout=config.SSH_TIMEOUT,
        check=False,
    )
    if completed.returncode != 0:
        err = completed.stderr.strip()
        LOGGER.error(
            "exit=%s stderr=%s", completed.returncode, err if err else "<empty>"
        )
    return CommandResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
    )


def _demo_runner(cmd, **_kwargs):
    """Return a minimal completed-process stand-in for doctests.

    Args:
        cmd (list[str]): Command tokens passed to the runner.
        **_kwargs: Unused keyword arguments.

    Returns:
        Any: Fake completed-process like object.
    """

    class DemoResult:
        def __init__(self, stdout: str) -> None:
            """Create a demo result container.

            Args:
                stdout (str): Fake stdout content.
            """
            self.stdout = stdout
            self.stderr = ""
            self.returncode = 0

    if "stat" in cmd:
        return DemoResult(stdout="1")
    return DemoResult(stdout="ok")


def run_command(
    spec: CommandSpec,
    args: dict[str, Any],
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Run a configured command spec via SSH.

    Args:
        spec (CommandSpec): The validated command specification.
        args (dict[str, Any]): Input arguments for the command.
        runner (Callable[..., subprocess.CompletedProcess[str]]): Runner override.

    Returns:
        CommandResult: Captured stdout/stderr and exit code.

    Examples:
        >>> import os
        >>> def fake_runner(cmd, **kwargs):
        ...     class FakeResult:
        ...         def __init__(self):
        ...             self.stdout = "ok"
        ...             self.stderr = ""
        ...             self.returncode = 0
        ...     return FakeResult()
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> spec = CommandSpec(
        ...     id="demo",
        ...     description="demo",
        ...     command=["echo", "{value}"],
        ...     params=[CommandParam(name="value", param_type="string", required=True)],
        ... )
        >>> run_command(spec, {"value": "hi"}, runner=fake_runner).stdout
        'ok'
    """
    param_map = {param.name: param for param in spec.params}
    extra_args = set(args) - set(param_map)
    if extra_args:
        raise CommandError(f"unexpected parameters: {sorted(extra_args)}")

    values: dict[str, Any] = {}
    for param in spec.params:
        if param.name in args:
            raw_value = args[param.name]
        elif param.default is not None:
            raw_value = param.default
        elif param.required:
            raise CommandError(f"missing required parameter: {param.name}")
        else:
            raw_value = None
        if raw_value is None:
            continue
        values[param.name] = _resolve_param_value(param, raw_value)

    placeholders = _collect_placeholders(spec.command)
    missing = sorted(
        name for name in placeholders if name in param_map and name not in values
    )
    if missing:
        raise CommandError(f"missing values for placeholders: {missing}")

    if spec.limits.max_bytes is not None and spec.limits.size_param:
        size_value = values.get(spec.limits.size_param)
        if size_value is None:
            raise CommandError("size check requires a path value")
        size = _remote_file_size(size_value, runner=runner)
        if size > spec.limits.max_bytes:
            raise CommandError("file is too large to process safely")

    rendered = _render_command_tokens(spec.command, values)
    return _run_ssh(rendered, runner=runner)


def _resolve_param_value(param: CommandParam, raw_value: Any) -> Any:
    """Resolve and validate a parameter value.

    Args:
        param (CommandParam): Parameter specification.
        raw_value (Any): Raw input value.

    Returns:
        Any: Normalized and validated value.
    """
    if param.value_map is not None:
        if not isinstance(raw_value, str):
            raise CommandError(f"param '{param.name}' must be a string")
        if raw_value not in param.value_map:
            raise CommandError(f"param '{param.name}' is not allowed")
        mapped_value: Any = param.value_map[raw_value]
    else:
        mapped_value = raw_value

    if param.allowed_values is not None:
        if not isinstance(raw_value, str):
            raise CommandError(f"param '{param.name}' must be a string")
        if raw_value not in param.allowed_values:
            raise CommandError(f"param '{param.name}' is not allowed")

    if param.param_type == "int":
        return _coerce_int(param, mapped_value)
    if param.param_type == "string":
        return _coerce_string(param, mapped_value)
    if param.param_type == "path":
        return _coerce_path(param, mapped_value)
    raise CommandError(f"unsupported param type: {param.param_type}")


def _coerce_int(param: CommandParam, value: Any) -> int:
    """Coerce and validate an integer parameter.

    Args:
        param (CommandParam): Parameter specification.
        value (Any): Raw value to coerce.

    Returns:
        int: Validated integer value.
    """
    if isinstance(value, bool):
        raise CommandError(f"param '{param.name}' must be an integer")
    if isinstance(value, int):
        int_value = value
    elif isinstance(value, str) and value.strip() != "":
        try:
            int_value = int(value)
        except ValueError as exc:
            raise CommandError(f"param '{param.name}' must be an integer") from exc
    else:
        raise CommandError(f"param '{param.name}' must be an integer")
    if param.min_value is not None and int_value < param.min_value:
        raise CommandError(f"param '{param.name}' is below minimum")
    if param.max_value is not None and int_value > param.max_value:
        raise CommandError(f"param '{param.name}' exceeds maximum")
    return int_value


def _coerce_string(param: CommandParam, value: Any) -> str:
    """Coerce and validate a string parameter.

    Args:
        param (CommandParam): Parameter specification.
        value (Any): Raw value to coerce.

    Returns:
        str: Validated string value.
    """
    if not isinstance(value, str) or value == "":
        raise CommandError(f"param '{param.name}' must be a non-empty string")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise CommandError(f"param '{param.name}' contains invalid characters")
    if param.max_length is not None and len(value) > param.max_length:
        raise CommandError(f"param '{param.name}' exceeds maximum length")
    return value


def _coerce_path(param: CommandParam, value: Any) -> str:
    """Coerce and validate a path parameter.

    Args:
        param (CommandParam): Parameter specification.
        value (Any): Raw path value.

    Returns:
        str: Normalized and validated path.
    """
    if not isinstance(value, str):
        raise CommandError(f"param '{param.name}' must be a string")
    allowed_prefixes = _resolve_allowed_prefixes(param)
    return _normalize_remote_path(value, allowed_prefixes)


def _resolve_allowed_prefixes(param: CommandParam) -> list[str]:
    """Resolve per-parameter allowed prefixes.

    Args:
        param (CommandParam): Parameter specification.

    Returns:
        list[str]: Allowed path prefixes.
    """
    base_prefixes = config.ALLOWED_PATH_PREFIXES
    if not base_prefixes:
        raise CommandError("allowed path prefixes are not configured")
    normalized_base = [_normalize_prefix(prefix) for prefix in base_prefixes]
    allowed = param.allowed
    if allowed is None or allowed == "all":
        return normalized_base
    if not isinstance(allowed, list):
        raise CommandError(f"allowed prefixes for '{param.name}' must be a list")
    normalized_allowed = [_normalize_prefix(prefix) for prefix in allowed]
    for prefix in normalized_allowed:
        if not _prefix_within_any(prefix, normalized_base):
            raise CommandError("allowed prefix is outside global allow-list")
    return normalized_allowed


def _normalize_prefix(prefix: str) -> str:
    """Normalize and validate a path prefix.

    Args:
        prefix (str): Prefix to normalize.

    Returns:
        str: Normalized prefix.
    """
    if not isinstance(prefix, str) or not prefix.strip():
        raise CommandError("allowed prefix must be a non-empty string")
    if "\x00" in prefix or "\n" in prefix or "\r" in prefix:
        raise CommandError("allowed prefix contains invalid characters")
    if not prefix.startswith("/"):
        raise CommandError("allowed prefix must be absolute")
    return posixpath.normpath(prefix)


def _prefix_within_any(prefix: str, bases: list[str]) -> bool:
    """Check whether a prefix is within any base path.

    Args:
        prefix (str): Prefix to test.
        bases (list[str]): Base prefixes to compare against.

    Returns:
        bool: True if prefix is within any base.
    """
    return any(
        prefix == base or prefix.startswith(base.rstrip("/") + "/") for base in bases
    )


def _base_context() -> dict[str, Any]:
    """Return the reserved placeholder context.

    Returns:
        dict[str, Any]: Placeholder values.
    """
    return {
        "ssh_user": config.SSH_USER,
        "max_grep_matches": config.MAX_GREP_MATCHES,
    }


def _collect_placeholders(command: list[str]) -> set[str]:
    """Collect placeholder names from command tokens.

    Args:
        command (list[str]): Command tokens to scan.

    Returns:
        set[str]: Placeholder field names.
    """
    formatter = string.Formatter()
    placeholders: set[str] = set()
    for token in command:
        try:
            for _, field_name, _, _ in formatter.parse(token):
                if field_name:
                    placeholders.add(field_name)
        except ValueError as exc:
            raise CommandError("invalid format token") from exc
    return placeholders


def _render_command_tokens(command: list[str], values: dict[str, Any]) -> list[str]:
    """Render command tokens using provided values.

    Args:
        command (list[str]): Command tokens with placeholders.
        values (dict[str, Any]): Placeholder values.

    Returns:
        list[str]: Rendered command tokens.
    """
    base_context = _base_context()
    conflicts = set(base_context) & set(values)
    if conflicts:
        raise CommandError(
            f"parameter conflicts with reserved context: {sorted(conflicts)}"
        )
    context = {**base_context, **values}
    rendered: list[str] = []
    for token in command:
        try:
            rendered.append(token.format_map(context))
        except KeyError as exc:
            raise CommandError(f"missing placeholder: {exc.args[0]}") from exc
        except ValueError as exc:
            raise CommandError("invalid format token") from exc
    return rendered


def squeue(
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Run squeue for the current user.

    Args:
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Examples:
        >>> import os
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> squeue(runner=_demo_runner).stdout
        'ok'
    """
    return _run_ssh(["squeue", "--me"], runner=runner)


def sacct(
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Run sacct with a fixed safe flag set.

    Args:
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Examples:
        >>> import os
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> sacct(runner=_demo_runner).stdout
        'ok'
    """
    return _run_ssh(["sacct", "-u", config.SSH_USER, "-X", "-n", "-P"], runner=runner)


def ls(
    path: str,
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """List directory contents at path.

    Args:
        path (str): Directory path to list.
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Examples:
        >>> import os
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> ls("/user/davide.mattioli/u20330/sample", runner=_demo_runner).stdout
        'ok'
    """
    norm = _normalize_remote_path(path)
    return _run_ssh(["ls", "-la", "--", norm], runner=runner)


def stat(
    path: str,
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Show stat info for a path.

    Args:
        path (str): File or directory path to inspect.
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Examples:
        >>> import os
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> stat("/user/davide.mattioli/u20330/sample", runner=_demo_runner).stdout
        '1'
    """
    norm = _normalize_remote_path(path)
    return _run_ssh(["stat", "--", norm], runner=runner)


def head(
    path: str,
    n: int,
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Show the first N lines of a file.

    Args:
        path (str): File path to read.
        n (int): Number of lines to return.
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Examples:
        >>> import os
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> head("/user/davide.mattioli/u20330/sample", 10, runner=_demo_runner).stdout
        'ok'
    """
    norm = _normalize_remote_path(path)
    if not (1 <= n <= config.MAX_HEAD_TAIL_LINES):
        raise CommandError("n is outside allowed range")
    return _run_ssh(["head", "-n", str(n), "--", norm], runner=runner)


def tail(
    path: str,
    n: int,
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Show the last N lines of a file.

    Args:
        path (str): File path to read.
        n (int): Number of lines to return.
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Examples:
        >>> import os
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> tail("/user/davide.mattioli/u20330/sample", 10, runner=_demo_runner).stdout
        'ok'
    """
    norm = _normalize_remote_path(path)
    if not (1 <= n <= config.MAX_HEAD_TAIL_LINES):
        raise CommandError("n is outside allowed range")
    return _run_ssh(["tail", "-n", str(n), "--", norm], runner=runner)


def _remote_file_size(
    path: str,
    runner: Callable[..., Any] = subprocess.run,
) -> int:
    """Return the remote file size in bytes.

    Args:
        path (str): File path to stat.
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Returns:
        int: File size in bytes.
    """
    norm = _normalize_remote_path(path)
    result = _run_ssh(["stat", "-c", "%s", "--", norm], runner=runner)
    if result.exit_code != 0:
        raise CommandError(result.stderr.strip() or "stat failed")
    try:
        return int(result.stdout.strip())
    except ValueError as exc:
        raise CommandError("stat returned non-numeric size") from exc


def cat(
    path: str,
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Cat a file with a size guard.

    Args:
        path (str): File path to read.
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Examples:
        >>> import os
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> cat("/user/davide.mattioli/u20330/sample", runner=_demo_runner).stdout
        'ok'
    """
    norm = _normalize_remote_path(path)
    size = _remote_file_size(norm, runner=runner)
    if size > config.MAX_CAT_BYTES:
        raise CommandError("file is too large to cat safely")
    return _run_ssh(["cat", "--", norm], runner=runner)


def grep(
    pattern: str,
    path: str,
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Run grep (recursive) with match limit.

    Args:
        pattern (str): Pattern to search for.
        path (str): Directory or file path to search.
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Examples:
        >>> import os
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> grep("token", "/user/davide.mattioli/u20330/sample", runner=_demo_runner).stdout
        'ok'
    """
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
        ],
        runner=runner,
    )


def sbatch(
    job_id: str,
    runner: Callable[..., Any] = subprocess.run,
) -> CommandResult:
    """Submit a whitelisted sbatch script by id.

    Args:
        job_id (str): Job id to submit.
        runner (Callable[..., Any]): Runner override for subprocess execution.

    Examples:
        >>> import os
        >>> os.environ["SSH_AUTH_SOCK"] = "test"
        >>> sbatch("run_main", runner=_demo_runner).stdout
        'ok'
    """
    _validate_token(job_id, "job_id")
    script_path = config.SBATCH_SCRIPTS.get(job_id)

    if not script_path:
        raise CommandError("job_id is not in the allow-list")

    norm = _normalize_remote_path(script_path)
    return _run_ssh(["sbatch", norm], runner=runner)
