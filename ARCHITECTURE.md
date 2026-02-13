# ARCHITECTURE

## Goal
Provide a safe, configuration-driven MCP server that exposes whitelisted SSH
commands for the cluster.

## Folder Structure
- `config.py` - runtime defaults and allow-lists.
- `commands.yml` - command definitions (tools, params, limits).
- `command_config.py` - YAML parser + schema validation.
- `ssh_guard.py` - path and token validation, SSH execution.
- `server.py` - tool registration and MCP entry point.
- `tests/` - parser and guard tests.

## Design Principles
- Safety by default (no shell, strict validation, allow-lists).
- Declarative command definitions in YAML.
- Deterministic parsing with clear errors.
- Non-interactive SSH with agent-based auth.
- Compatibility-first hardening flags for gradual security rollout.

## Workflow
1. Update `commands.yml` to add or change tools.
2. `command_config.py` parses + validates the config on startup.
3. `server.py` registers each command as an MCP tool dynamically.
4. `ssh_guard.py` enforces path and argument restrictions before SSH.
5. Optional strict mode enforces host-key verification, canonical path checks,
   and duplicate YAML key rejection.
