"""Example configuration for the cluster MCP tools."""

from __future__ import annotations

SSH_USER = "your_user"
SSH_HOST = "your.ssh.host"
SSH_KEY = "/home/your_user/.ssh/your_key"
SSH_TIMEOUT = 60
SSH_CONNECT_TIMEOUT = 15
SSH_BATCH_MODE = True
LOG_PATH = "/path/to/cluster_tools.log"
LOG_LEVEL = "INFO"

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
    "run_main": "/user/your.username/project/jobs/run_main.sh",
    "run_split_eval": "/user/your.username/project/jobs/run_split_eval.sh",
}

COMMANDS_CONFIG_PATH = "commands.yml"
COMMANDS_CONFIG_VERSION = 1
RESERVED_COMMAND_CONTEXT_KEYS = {
    "ssh_user",
    "max_grep_matches",
}
