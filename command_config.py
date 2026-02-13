"""Parse and validate YAML command configuration for MCP tools."""

from __future__ import annotations

import logging
import re
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import config


class CommandConfigError(ValueError):
    """Raised when the command configuration is invalid.

    Examples:
        >>> isinstance(CommandConfigError("bad config"), ValueError)
        True
    """


@dataclass(frozen=True)
class CommandLimits:
    """Limits that apply to a configured command.

    Examples:
        >>> CommandLimits(max_lines=100, max_bytes=None, size_param=None).max_lines
        100
    """

    max_lines: int | None = None
    max_bytes: int | None = None
    size_param: str | None = None


@dataclass(frozen=True)
class CommandParam:
    """A parameter definition for a configured command.

    Examples:
        >>> param = CommandParam(name="path", param_type="path", required=True)
        >>> param.name
        'path'
    """

    name: str
    param_type: str
    required: bool = True
    allowed: list[str] | str | None = None
    allowed_values: list[str] | None = None
    value_map: dict[str, str] | None = None
    min_value: int | None = None
    max_value: int | None = None
    max_length: int | None = None
    default: Any | None = None
    description: str | None = None


@dataclass(frozen=True)
class CommandSpec:
    """A fully validated command specification.

    Examples:
        >>> spec = CommandSpec(id="demo", description="Demo", command=["echo"], params=[])
        >>> spec.id
        'demo'
    """

    id: str
    description: str
    command: list[str]
    params: list[CommandParam]
    limits: CommandLimits = CommandLimits()


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LOGGER = logging.getLogger("cluster_tools")


def parse_yaml(text: str) -> Any:
    """Parse a restricted YAML subset into Python objects.

    Args:
        text (str): YAML text to parse.

    Returns:
        Any: Parsed data structure (dicts/lists/scalars).

    Examples:
        >>> sample = (
        ...     "version: 1\\n"
        ...     "commands:\\n"
        ...     "  - id: demo\\n"
        ...     "    description: Demo command\\n"
        ...     "    command:\\n"
        ...     "      - echo\\n"
        ...     "      - \\\"{ssh_user}\\\"\\n"
        ... )
        >>> data = parse_yaml(sample)
        >>> data["version"]
        1
        >>> data["commands"][0]["id"]
        'demo'
    """
    lines = _prepare_lines(text)
    if not lines:
        raise CommandConfigError("configuration is empty")
    result, next_index = _parse_block(lines, 0, 0)
    if next_index != len(lines):
        line = lines[next_index]
        raise CommandConfigError(f"unexpected content at line {line.line_no}")
    return result


def load_command_config(path: str | Path) -> list[CommandSpec]:
    """Load and validate the command configuration file.

    Args:
        path (str | Path): Path to the YAML file.

    Returns:
        list[CommandSpec]: Validated command specifications.

    Examples:
        >>> import tempfile
        >>> from pathlib import Path
        >>> content = (
        ...     "version: 1\\n"
        ...     "commands:\\n"
        ...     "  - id: demo\\n"
        ...     "    description: Demo command\\n"
        ...     "    command:\\n"
        ...     "      - echo\\n"
        ... )
        >>> with tempfile.TemporaryDirectory() as tmp:
        ...     cfg = Path(tmp) / "commands.yml"
        ...     _ = cfg.write_text(content)
        ...     load_command_config(cfg)[0].id
        'demo'
    """
    config_path = Path(path)
    data = parse_yaml(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CommandConfigError("top-level YAML must be a mapping")
    version = data.get("version")
    if version != config.COMMANDS_CONFIG_VERSION:
        raise CommandConfigError("unsupported config version")
    commands = data.get("commands")
    if not isinstance(commands, list):
        raise CommandConfigError("commands must be a list")

    specs: list[CommandSpec] = []
    seen_ids: set[str] = set()
    for entry in commands:
        if not isinstance(entry, dict):
            raise CommandConfigError("each command must be a mapping")
        spec = _parse_command(entry)
        if spec.id in seen_ids:
            raise CommandConfigError(f"duplicate command id: {spec.id}")
        seen_ids.add(spec.id)
        specs.append(spec)
    return specs


@dataclass(frozen=True)
class _YamlLine:
    indent: int
    content: str
    line_no: int


def _prepare_lines(text: str) -> list[_YamlLine]:
    """Normalize YAML content into trimmed, indented lines.

    Args:
        text (str): Raw YAML input.

    Returns:
        list[_YamlLine]: Parsed line entries with indentation metadata.
    """
    lines: list[_YamlLine] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw[: len(raw) - len(raw.lstrip(" "))]:
            raise CommandConfigError(f"tabs are not allowed (line {line_no})")
        cleaned = _strip_comment(raw).rstrip()
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        if indent % 2 != 0:
            raise CommandConfigError(f"indent must be multiple of 2 (line {line_no})")
        lines.append(
            _YamlLine(indent=indent, content=cleaned.lstrip(" "), line_no=line_no)
        )
    return lines


def _strip_comment(line: str) -> str:
    """Remove comments from a line, respecting quotes.

    Args:
        line (str): Raw line content.

    Returns:
        str: Line content without comments.
    """
    in_single = False
    in_double = False
    result = []
    for char in line:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            break
        result.append(char)
    return "".join(result)


def _parse_block(lines: list[_YamlLine], index: int, indent: int) -> tuple[Any, int]:
    """Parse a YAML block at the current indentation.

    Args:
        lines (list[_YamlLine]): Prepared lines.
        index (int): Current line index.
        indent (int): Expected indentation level.

    Returns:
        tuple[Any, int]: Parsed value and next index.
    """
    if index >= len(lines):
        raise CommandConfigError("unexpected end of configuration")
    if lines[index].indent < indent:
        raise CommandConfigError("unexpected indentation")
    if lines[index].indent > indent:
        raise CommandConfigError(
            f"unexpected indentation at line {lines[index].line_no}"
        )
    if lines[index].content.startswith("- "):
        return _parse_list(lines, index, indent)
    return _parse_dict(lines, index, indent)


def _parse_dict(
    lines: list[_YamlLine], index: int, indent: int
) -> tuple[dict[str, Any], int]:
    """Parse a YAML mapping block.

    Args:
        lines (list[_YamlLine]): Prepared lines.
        index (int): Current line index.
        indent (int): Mapping indentation level.

    Returns:
        tuple[dict[str, Any], int]: Parsed mapping and next index.
    """
    mapping: dict[str, Any] = {}
    while index < len(lines) and lines[index].indent == indent:
        content = lines[index].content
        if content.startswith("- "):
            raise CommandConfigError(
                f"unexpected list item at line {lines[index].line_no}"
            )
        key, sep, rest = content.partition(":")
        if not sep:
            raise CommandConfigError(f"missing ':' at line {lines[index].line_no}")
        key = key.strip()
        if not key:
            raise CommandConfigError(f"empty key at line {lines[index].line_no}")
        rest = rest.strip()
        if rest == "":
            index += 1
            if index >= len(lines) or lines[index].indent <= indent:
                raise CommandConfigError(
                    f"missing value for '{key}' at line {lines[index - 1].line_no}"
                )
            value, index = _parse_block(lines, index, indent + 2)
        else:
            value = _parse_value(rest)
            index += 1
        if key in mapping:
            _handle_duplicate_key(key, lines[index - 1].line_no)
        mapping[key] = value
    return mapping, index


def _handle_duplicate_key(key: str, line_no: int) -> None:
    """Handle duplicate mapping keys according to compatibility mode.

    Args:
        key (str): Duplicate key name.
        line_no (int): Source line number.

    Raises:
        CommandConfigError: If strict duplicate-key rejection is enabled.
    """
    message = f"duplicate key '{key}' at line {line_no}"
    if getattr(config, "REJECT_DUPLICATE_YAML_KEYS", False):
        raise CommandConfigError(message)
    LOGGER.warning("%s (compat mode: last value wins)", message)


def _parse_list(
    lines: list[_YamlLine], index: int, indent: int
) -> tuple[list[Any], int]:
    """Parse a YAML sequence block.

    Args:
        lines (list[_YamlLine]): Prepared lines.
        index (int): Current line index.
        indent (int): Sequence indentation level.

    Returns:
        tuple[list[Any], int]: Parsed list and next index.
    """
    items: list[Any] = []
    while index < len(lines) and lines[index].indent == indent:
        content = lines[index].content
        if not content.startswith("- "):
            raise CommandConfigError(
                f"expected list item at line {lines[index].line_no}"
            )
        item_content = content[2:].strip()
        if item_content == "":
            index += 1
            if index >= len(lines) or lines[index].indent <= indent:
                raise CommandConfigError(
                    f"missing list item at line {lines[index - 1].line_no}"
                )
            item, index = _parse_block(lines, index, indent + 2)
            items.append(item)
            continue
        if _looks_like_mapping(item_content):
            key, _, rest = item_content.partition(":")
            key = key.strip()
            rest = rest.strip()
            item_dict: dict[str, Any] = {}
            if rest == "":
                index += 1
                if index >= len(lines) or lines[index].indent <= indent:
                    raise CommandConfigError(
                        f"missing value for '{key}' at line {lines[index - 1].line_no}"
                    )
                value, index = _parse_block(lines, index, indent + 2)
            else:
                value = _parse_value(rest)
                index += 1
            item_dict[key] = value
            if index < len(lines) and lines[index].indent == indent + 2:
                extra, index = _parse_dict(lines, index, indent + 2)
                overlap = set(item_dict) & set(extra)
                if overlap:
                    raise CommandConfigError(
                        f"duplicate keys in list item: {sorted(overlap)}"
                    )
                item_dict.update(extra)
            items.append(item_dict)
        else:
            items.append(_parse_value(item_content))
            index += 1
    return items, index


def _looks_like_mapping(value: str) -> bool:
    """Return True if the value resembles a mapping entry.

    Args:
        value (str): YAML token to inspect.

    Returns:
        bool: True if the token looks like a mapping.
    """
    if not value:
        return False
    if value.startswith("'") or value.startswith('"'):
        return False
    key, sep, _ = value.partition(":")
    return bool(sep and key.strip())


def _parse_value(token: str) -> Any:
    """Parse a scalar or inline list token.

    Args:
        token (str): Token to parse.

    Returns:
        Any: Parsed scalar or list.
    """
    token = token.strip()
    if token.startswith("[") and token.endswith("]"):
        return _parse_inline_list(token)
    return _parse_scalar(token)


def _parse_inline_list(token: str) -> list[Any]:
    """Parse a YAML inline list token.

    Args:
        token (str): Inline list token.

    Returns:
        list[Any]: Parsed list values.
    """
    content = token[1:-1].strip()
    if not content:
        return []
    parts = _split_inline_list(content)
    return [_parse_scalar(part.strip()) for part in parts]


def _split_inline_list(content: str) -> list[str]:
    """Split inline list content into raw items.

    Args:
        content (str): Inline list content without brackets.

    Returns:
        list[str]: Raw list item strings.
    """
    parts: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    for char in content:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if char == "," and not in_single and not in_double:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _parse_scalar(token: str) -> Any:
    """Parse a scalar token into a Python value.

    Args:
        token (str): Scalar token.

    Returns:
        Any: Parsed scalar value.
    """
    if token == "null" or token == "None":
        return None
    if token == "true":
        return True
    if token == "false":
        return False
    if token.startswith("'") and token.endswith("'") and len(token) >= 2:
        return token[1:-1]
    if token.startswith('"') and token.endswith('"') and len(token) >= 2:
        return token[1:-1]
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    return token


def _parse_command(entry: dict[str, Any]) -> CommandSpec:
    """Convert a command mapping into a CommandSpec.

    Args:
        entry (dict[str, Any]): Raw command mapping.

    Returns:
        CommandSpec: Validated command specification.
    """
    command_id = _require_str(entry.get("id"), "id")
    if not _IDENTIFIER_RE.fullmatch(command_id):
        raise CommandConfigError(f"invalid command id: {command_id}")
    description = _require_str(entry.get("description"), "description")
    command = entry.get("command")
    if not isinstance(command, list) or not command:
        raise CommandConfigError(f"command '{command_id}' must define command tokens")
    command_tokens = [
        _require_str(token, f"command token for {command_id}") for token in command
    ]

    params_data = entry.get("params") or {}
    if not isinstance(params_data, dict):
        raise CommandConfigError(f"params for '{command_id}' must be a mapping")
    params = [
        _parse_param(name, value, command_id) for name, value in params_data.items()
    ]

    limits = _parse_limits(entry.get("limits"), command_id)
    _validate_placeholders(command_tokens, params, command_id)
    _validate_limits(limits, params, command_id)

    return CommandSpec(
        id=command_id,
        description=description,
        command=command_tokens,
        params=params,
        limits=limits,
    )


def _parse_param(name: str, value: Any, command_id: str) -> CommandParam:
    """Parse a parameter mapping into CommandParam.

    Args:
        name (str): Parameter name.
        value (Any): Parameter definition mapping.
        command_id (str): Owning command id.

    Returns:
        CommandParam: Validated parameter definition.
    """
    if not _IDENTIFIER_RE.fullmatch(name):
        raise CommandConfigError(f"invalid param name '{name}' in '{command_id}'")
    if name in config.RESERVED_COMMAND_CONTEXT_KEYS:
        raise CommandConfigError(
            f"param '{name}' conflicts with reserved context in '{command_id}'"
        )
    if not isinstance(value, dict):
        raise CommandConfigError(f"param '{name}' in '{command_id}' must be a mapping")
    param_type = _require_str(value.get("type"), f"param '{name}' type")
    if param_type not in {"path", "string", "int"}:
        raise CommandConfigError(f"invalid type for param '{name}' in '{command_id}'")
    required = _require_bool(value.get("required", True), f"param '{name}' required")

    default = value.get("default")
    if default is not None and required:
        raise CommandConfigError(
            f"param '{name}' in '{command_id}' cannot be required with default"
        )
    if default is not None:
        if param_type == "int" and not isinstance(default, int):
            raise CommandConfigError(f"default for '{name}' must be an integer")
        if param_type in {"string", "path"} and not isinstance(default, str):
            raise CommandConfigError(f"default for '{name}' must be a string")

    allowed = value.get("allowed")
    if allowed is not None:
        if param_type != "path":
            raise CommandConfigError(
                f"allowed is only valid for path params ('{name}')"
            )
        if isinstance(allowed, str):
            if allowed != "all":
                raise CommandConfigError(f"allowed must be 'all' or list for '{name}'")
        elif isinstance(allowed, list):
            if not allowed:
                raise CommandConfigError(f"allowed list for '{name}' cannot be empty")
            if not all(isinstance(item, str) for item in allowed):
                raise CommandConfigError(f"allowed list for '{name}' must be strings")
        else:
            raise CommandConfigError(f"allowed must be 'all' or list for '{name}'")

    allowed_values = value.get("allowed_values")
    if allowed_values is not None:
        if not isinstance(allowed_values, list) or not all(
            isinstance(item, str) for item in allowed_values
        ):
            raise CommandConfigError(
                f"allowed_values for '{name}' must be a list of strings"
            )

    value_map = value.get("value_map")
    if value_map is not None:
        if not isinstance(value_map, dict) or not all(
            isinstance(key, str) and isinstance(val, str)
            for key, val in value_map.items()
        ):
            raise CommandConfigError(
                f"value_map for '{name}' must map strings to strings"
            )
        if allowed_values is None:
            allowed_values = sorted(value_map.keys())
        elif set(allowed_values) != set(value_map.keys()):
            raise CommandConfigError(
                f"allowed_values and value_map keys must match for '{name}'"
            )

    min_value = _require_int(value.get("min"), f"param '{name}' min", allow_none=True)
    max_value = _require_int(value.get("max"), f"param '{name}' max", allow_none=True)
    if param_type != "int" and (min_value is not None or max_value is not None):
        raise CommandConfigError(f"min/max only allowed for int params ('{name}')")
    if min_value is not None and max_value is not None and min_value > max_value:
        raise CommandConfigError(f"min cannot exceed max for '{name}'")

    max_length = _require_int(
        value.get("max_length"), f"param '{name}' max_length", allow_none=True
    )
    if param_type != "string" and max_length is not None:
        raise CommandConfigError(
            f"max_length only allowed for string params ('{name}')"
        )

    description = value.get("description")
    if description is not None and not isinstance(description, str):
        raise CommandConfigError(f"description for '{name}' must be a string")

    return CommandParam(
        name=name,
        param_type=param_type,
        required=required,
        allowed=allowed,
        allowed_values=allowed_values,
        value_map=value_map,
        min_value=min_value,
        max_value=max_value,
        max_length=max_length,
        default=default,
        description=description,
    )


def _parse_limits(limits: Any, command_id: str) -> CommandLimits:
    """Parse command limits configuration.

    Args:
        limits (Any): Raw limits mapping.
        command_id (str): Owning command id.

    Returns:
        CommandLimits: Parsed limits.
    """
    if limits is None:
        return CommandLimits()
    if not isinstance(limits, dict):
        raise CommandConfigError(f"limits for '{command_id}' must be a mapping")
    max_lines = _require_int(limits.get("max_lines"), "max_lines", allow_none=True)
    max_bytes = _require_int(limits.get("max_bytes"), "max_bytes", allow_none=True)
    if max_lines is not None and max_lines <= 0:
        raise CommandConfigError(f"max_lines for '{command_id}' must be > 0")
    if max_bytes is not None and max_bytes <= 0:
        raise CommandConfigError(f"max_bytes for '{command_id}' must be > 0")
    size_param = limits.get("size_param")
    if size_param is not None and not isinstance(size_param, str):
        raise CommandConfigError(f"size_param for '{command_id}' must be a string")
    if size_param is not None and max_bytes is None:
        raise CommandConfigError(
            f"size_param for '{command_id}' requires max_bytes to be set"
        )
    return CommandLimits(
        max_lines=max_lines, max_bytes=max_bytes, size_param=size_param
    )


def _validate_placeholders(
    command: list[str], params: list[CommandParam], command_id: str
) -> None:
    """Validate that placeholders match params or reserved context.

    Args:
        command (list[str]): Command tokens.
        params (list[CommandParam]): Declared parameters.
        command_id (str): Command identifier.
    """
    param_names = {param.name for param in params}
    reserved = set(config.RESERVED_COMMAND_CONTEXT_KEYS)
    formatter = string.Formatter()
    placeholders: set[str] = set()
    for token in command:
        try:
            for _, field_name, _, _ in formatter.parse(token):
                if field_name:
                    placeholders.add(field_name)
        except ValueError as exc:
            raise CommandConfigError(f"invalid format token in '{command_id}'") from exc

    unknown = placeholders - param_names - reserved
    if unknown:
        raise CommandConfigError(
            f"unknown placeholders in '{command_id}': {sorted(unknown)}"
        )


def _validate_limits(
    limits: CommandLimits, params: list[CommandParam], command_id: str
) -> None:
    """Validate that limits reference valid parameters.

    Args:
        limits (CommandLimits): Limits configuration.
        params (list[CommandParam]): Declared parameters.
        command_id (str): Command identifier.
    """
    if limits.size_param is None:
        return
    param_names = {param.name: param for param in params}
    param = param_names.get(limits.size_param)
    if not param:
        raise CommandConfigError(
            f"size_param '{limits.size_param}' not found in '{command_id}'"
        )
    if param.param_type != "path":
        raise CommandConfigError(
            f"size_param '{limits.size_param}' must be a path param in '{command_id}'"
        )


def _require_str(value: Any, label: str) -> str:
    """Require a non-empty string value.

    Args:
        value (Any): Value to validate.
        label (str): Field label for errors.

    Returns:
        str: Validated string value.
    """
    if not isinstance(value, str) or not value.strip():
        raise CommandConfigError(f"{label} must be a non-empty string")
    return value


def _require_bool(value: Any, label: str) -> bool:
    """Require a boolean value.

    Args:
        value (Any): Value to validate.
        label (str): Field label for errors.

    Returns:
        bool: Validated boolean value.
    """
    if isinstance(value, bool):
        return value
    raise CommandConfigError(f"{label} must be a boolean")


def _require_int(value: Any, label: str, allow_none: bool = False) -> int | None:
    """Require an integer value.

    Args:
        value (Any): Value to validate.
        label (str): Field label for errors.
        allow_none (bool): Allow None values.

    Returns:
        int | None: Validated integer value.
    """
    if value is None and allow_none:
        return None
    if isinstance(value, bool):
        raise CommandConfigError(f"{label} must be an integer")
    if isinstance(value, int):
        return value
    raise CommandConfigError(f"{label} must be an integer")
