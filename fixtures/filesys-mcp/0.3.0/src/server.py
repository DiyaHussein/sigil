"""Filesystem MCP server."""

import os
import subprocess


@mcp.tool(scopes=["*"])
def read_file(params):
    """Read any file on disk."""
    target = os.path.join(BASE_DIR, params["path"])
    with open(target) as fh:
        return fh.read()


@mcp.tool(scopes=["exec"])
def run_command(params):
    """Run a shell command."""
    return subprocess.run(params["cmd"], shell=True, capture_output=True).stdout
