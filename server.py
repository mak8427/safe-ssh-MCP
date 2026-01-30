"""MCP server exposing safe cluster commands via SSH."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import ssh_guard

mcp = FastMCP("cluster-tools")


def _as_dict(result: ssh_guard.CommandResult) -> dict:
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
    }


@mcp.tool()
def cluster_squeue() -> dict:
    """Run squeue for the current user."""
    return _as_dict(ssh_guard.squeue())


@mcp.tool()
def cluster_sacct() -> dict:
    """Run sacct for the current user."""
    return _as_dict(ssh_guard.sacct())


@mcp.tool()
def cluster_ls(path: str) -> dict:
    """List directory contents at path."""
    return _as_dict(ssh_guard.ls(path))


@mcp.tool()
def cluster_stat(path: str) -> dict:
    """Show stat info for a path."""
    return _as_dict(ssh_guard.stat(path))


@mcp.tool()
def cluster_head(path: str, n: int = 200) -> dict:
    """Show the first N lines of a file."""
    return _as_dict(ssh_guard.head(path, n))


@mcp.tool()
def cluster_tail(path: str, n: int = 200) -> dict:
    """Show the last N lines of a file."""
    return _as_dict(ssh_guard.tail(path, n))


@mcp.tool()
def cluster_cat(path: str) -> dict:
    """Cat a file with a size guard."""
    return _as_dict(ssh_guard.cat(path))


@mcp.tool()
def cluster_grep(pattern: str, path: str) -> dict:
    """Search files or directories for a pattern."""
    return _as_dict(ssh_guard.grep(pattern, path))


@mcp.tool()
def cluster_sbatch(job_id: str) -> dict:
    """Submit a whitelisted sbatch script by id."""
    return _as_dict(ssh_guard.sbatch(job_id))


if __name__ == "__main__":
    mcp.run()
