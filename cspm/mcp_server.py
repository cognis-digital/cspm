"""CSPM MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
from cspm.core import load_config, scan


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
    def cspm_scan(config_path: str) -> str:
        """Cloud security posture from a config export (public buckets, open SGs,
        weak IAM). Accepts a path to a JSON config export. Returns JSON findings."""
        try:
            config = load_config(config_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return json.dumps({"error": str(exc)})
        findings = scan(config)
        return json.dumps(
            {"total": len(findings), "findings": [f.to_dict() for f in findings]},
            indent=2,
        )

    app.run()
    return 0
