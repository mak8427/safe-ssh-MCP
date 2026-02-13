# Changelog

## [0.1.3]
- Description: Add compatibility-first security hardening for SSH trust, path checks, and YAML validation.
- file touched: config_example.py, command_config.py, ssh_guard.py, server.py, commands.yml, README.md, ARCHITECTURE.md, tests/, CHANGELOG.md
- reason: Improve safety without breaking existing workflows by default.
- problems fixed: Adds strict host-key and canonical-path enforcement flags, validates runtime config at startup, rejects invalid limits, and supports duplicate-key warn-or-reject modes.

## [0.1.2]
- Description: Add SSH agent socket auto-discovery fallback when `SSH_AUTH_SOCK` is missing.
- file touched: ssh_guard.py, tests/test_ssh_guard.py, CHANGELOG.md
- reason: Prevent false "SSH agent is required" failures in service and tool-call contexts with stable socket paths.
- problems fixed: `squeue`/SSH commands now recover automatically when env propagation is incomplete.

## [0.1.0]
- Description: Add YAML-configured command registry with dynamic tool creation.
- file touched: commands.yml, command_config.py, server.py, ssh_guard.py, config.py, README.md, ARCHITECTURE.md, tests/, scripts/, .pre-commit-config.yaml, config_example.py
- reason: Allow safe, editable command definitions with per-command restrictions.
- problems fixed: Extended allow-list to include the shared /mnt path; added virtual cd tool; documented YAML schema; re-added redacted example config; sanitized README.

EXAMPLE
## [0.0.1]
- Description:
- file touched:
- reason:
- problems fixed:
