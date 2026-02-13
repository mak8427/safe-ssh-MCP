"""Example configuration for the cluster MCP tools."""

from __future__ import annotations

import os
import posixpath


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable.

    Args:
        name (str): Environment variable name.
        default (bool): Default value when variable is unset.

    Returns:
        bool: Parsed boolean value.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


SSH_USER = "your_user"
SSH_HOST = "your.ssh.host"
SSH_KEY = "/home/your_user/.ssh/your_key"
SSH_TIMEOUT = 60
SSH_CONNECT_TIMEOUT = 15
SSH_BATCH_MODE = True
LOG_PATH = "/path/to/cluster_tools.log"
LOG_LEVEL = "INFO"
SSH_KNOWN_HOSTS_FILE = "/home/your_user/.ssh/known_hosts"

ENFORCE_STRICT_HOST_KEY_CHECKING = _env_bool(
    "CLUSTER_TOOLS_ENFORCE_STRICT_HOST_KEY_CHECKING", False
)
ENFORCE_CANONICAL_PATH_CHECKS = _env_bool(
    "CLUSTER_TOOLS_ENFORCE_CANONICAL_PATH_CHECKS", False
)
REJECT_DUPLICATE_YAML_KEYS = _env_bool(
    "CLUSTER_TOOLS_REJECT_DUPLICATE_YAML_KEYS", False
)
ALLOW_INSECURE_SSH = _env_bool("CLUSTER_TOOLS_ALLOW_INSECURE_SSH", True)

BASE_PATH = "/user/your.username/"
ALLOWED_PATH_PREFIXES = [
    BASE_PATH,
    "/mnt/vast-standard/home/your.username/",
]

MAX_HEAD_TAIL_LINES = 2000
MAX_CAT_BYTES = 5 * 1024 * 1024
MAX_GREP_MATCHES = 500
MAX_GREP_PATTERN_LEN = 200

SBATCH_SCRIPTS = {
    "silver_set": "/user/your.username/project/silver_set.sh",
}

COMMANDS_CONFIG_PATH = "commands.yml"
COMMANDS_CONFIG_VERSION = 1
RESERVED_COMMAND_CONTEXT_KEYS = {
    "ssh_user",
    "max_grep_matches",
}


def validate_runtime_config() -> None:
    """Validate runtime configuration before server startup.

    Raises:
        ValueError: If required settings are missing or contradictory.
    """
    if not SSH_USER or not isinstance(SSH_USER, str):
        raise ValueError("SSH_USER must be a non-empty string")
    if not SSH_HOST or not isinstance(SSH_HOST, str):
        raise ValueError("SSH_HOST must be a non-empty string")
    if not SSH_KEY or not isinstance(SSH_KEY, str):
        raise ValueError("SSH_KEY must be a non-empty string")
    if SSH_TIMEOUT <= 0:
        raise ValueError("SSH_TIMEOUT must be > 0")
    if SSH_CONNECT_TIMEOUT <= 0:
        raise ValueError("SSH_CONNECT_TIMEOUT must be > 0")
    if not isinstance(ALLOWED_PATH_PREFIXES, list) or not ALLOWED_PATH_PREFIXES:
        raise ValueError("ALLOWED_PATH_PREFIXES must be a non-empty list")
    for prefix in ALLOWED_PATH_PREFIXES:
        if not isinstance(prefix, str) or not prefix.startswith("/"):
            raise ValueError("allowed path prefixes must be absolute strings")
    if ENFORCE_STRICT_HOST_KEY_CHECKING:
        if not SSH_KNOWN_HOSTS_FILE:
            raise ValueError(
                "SSH_KNOWN_HOSTS_FILE must be set when strict host key checking is enabled"
            )
        known_hosts = posixpath.normpath(SSH_KNOWN_HOSTS_FILE)
        if not known_hosts.startswith("/"):
            raise ValueError("SSH_KNOWN_HOSTS_FILE must be an absolute path")
    elif not ALLOW_INSECURE_SSH:
        raise ValueError(
            "ALLOW_INSECURE_SSH must be true when strict host key checking is disabled"
        )
