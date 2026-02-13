"""MCP server exposing safe cluster commands via SSH."""

from __future__ import annotations

import inspect
import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

import command_config
import config
import ssh_guard

mcp = FastMCP("cluster-tools")

LOGGER = logging.getLogger("cluster_tools")


def _as_dict(result: ssh_guard.CommandResult) -> dict:
    """Convert a CommandResult into a response dict.

    Args:
        result (ssh_guard.CommandResult): Command execution result.

    Returns:
        dict: Response payload.
    """
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
    }


def _safe_call(func, *args, **kwargs) -> dict:
    """Invoke a function and normalize errors for the client.

    Args:
        func (callable): Function to call.
        *args: Positional arguments.
        **kwargs: Keyword arguments.

    Returns:
        dict: Response payload with stdout/stderr/exit_code.
    """
    try:
        return _as_dict(func(*args, **kwargs))
    except Exception as exc:  # pragma: no cover - returns error to client
        LOGGER.error("tool error: %s", exc)
        return {
            "stdout": "",
            "stderr": str(exc),
            "exit_code": 1,
            "error": str(exc),
        }


def _build_signature(spec: command_config.CommandSpec) -> inspect.Signature:
    """Build a call signature for a command spec.

    Args:
        spec (command_config.CommandSpec): Command specification.

    Returns:
        inspect.Signature: Callable signature for MCP registration.
    """
    params = []
    for param in spec.params:
        if param.required and param.default is None:
            default = inspect.Parameter.empty
        elif param.default is None:
            default = None
        else:
            default = param.default
        annotation = int if param.param_type == "int" else str
        params.append(
            inspect.Parameter(
                param.name,
                inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=annotation,
            )
        )
    return inspect.Signature(params)


def _build_tool(spec: command_config.CommandSpec):
    """Create a tool function for a command spec.

    Args:
        spec (command_config.CommandSpec): Command specification.

    Returns:
        callable: Tool function bound to the command spec.
    """

    def tool_func(**kwargs) -> dict:
        """Execute the configured command with provided args.

        Args:
            **kwargs: Command arguments to pass through.

        Returns:
            dict: Command execution response.
        """
        return _safe_call(ssh_guard.run_command, spec, kwargs)

    tool_func.__name__ = spec.id
    tool_func.__doc__ = spec.description
    setattr(tool_func, "__signature__", _build_signature(spec))
    return tool_func


def _register_command_tools() -> None:
    """Load command specs and register MCP tools.

    This keeps tool registration in sync with commands.yml.
    """
    validate_runtime_config = getattr(config, "validate_runtime_config", None)
    if callable(validate_runtime_config):
        validate_runtime_config()
    config_path = Path(config.COMMANDS_CONFIG_PATH)
    if not config_path.is_absolute():
        config_path = Path(__file__).resolve().parent / config_path
    specs = command_config.load_command_config(config_path)
    for spec in specs:
        mcp.tool()(_build_tool(spec))


_register_command_tools()


if __name__ == "__main__":
    mcp.run()
