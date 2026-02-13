# Cluster MCP Tools

This is a minimal local MCP server that exposes a strict set of cluster commands via SSH.
It is designed to be safe by default and only allows whitelisted commands and paths.

## Requirements
- Python 3.9+
- SSH key (example): `~/.ssh/your_key`
- MCP Python package (one of these should work):
  - `pip install mcp`

## Run the MCP server
```bash
cd ~/tools/mcp/cluster_tools
python server.py
```

## Command configuration
Commands are defined in `commands.yml`. Each entry declares the tool name, params,
limits, and command tokens. Paths are validated against the allow-list in
`config.py` (`ALLOWED_PATH_PREFIXES`).

To add a new tool:
1. Add a new entry under `commands` in `commands.yml`.
2. Restart the MCP server.

Built-in placeholders available in command tokens:
- `{ssh_user}`
- `{max_grep_matches}`

`allowed: all` means "any path under the global allow-list".

### Minimal schema
```yaml
version: 1
commands:
  - id: cluster_ls
    description: List directory contents at path.
    command:
      - ls
      - -la
      - --
      - "{path}"
    params:
      path:
        type: path
        required: true
        allowed: all
```

### Common fields
- `id`: tool name (snake_case)
- `description`: short human-readable summary
- `command`: list of tokens, no shell
- `params`: map of parameter definitions
- `limits`: optional safety limits

### Parameter types
- `path`: absolute path, validated against allow-list
- `string`: non-empty string
- `int`: integer with optional `min`/`max`

### Optional parameter fields
- `allowed`: `all` or list of allowed path prefixes (for `path` only)
- `allowed_values`: enum list for `string` values
- `value_map`: map from user value to command token value
- `max_length`: max length for `string`
- `default`: default when `required: false`

### Virtual commands
`cluster_cd` validates a path and returns it without running SSH. It is useful
for client-side working directory selection.

## Security compatibility flags
This repository currently defaults to compatibility mode for security rollouts.
You can enable stricter behavior with environment variables:

- `CLUSTER_TOOLS_ENFORCE_STRICT_HOST_KEY_CHECKING=true`
- `CLUSTER_TOOLS_SSH_KNOWN_HOSTS_FILE=/absolute/path/to/known_hosts`
- `CLUSTER_TOOLS_ENFORCE_CANONICAL_PATH_CHECKS=true`
- `CLUSTER_TOOLS_REJECT_DUPLICATE_YAML_KEYS=true`

In compatibility mode, warnings are emitted and previous behavior is preserved.

## SSH agent requirement
This server runs with `BatchMode=yes`. Passphrase-protected keys must be loaded
via an SSH agent before starting the server (for example, `ssh-agent` +
`ssh-add`).

## Safety rules
- No arbitrary command execution.
- No shell metacharacters.
- Path allow-list enforced.
- Output and file size limits are enforced.
- Strict SSH host verification and canonical path checks are available as
  opt-in hardening flags.
