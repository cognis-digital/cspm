"""CSPM MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from cspm.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-cspm[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-cspm[mcp]'")
        return 1
    app = FastMCP("cspm")

    @app.tool()
    def cspm_scan(target: str) -> str:
        """Cloud security posture from a config export (public buckets, open SGs, weak IAM). Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
