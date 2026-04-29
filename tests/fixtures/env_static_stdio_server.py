from __future__ import annotations

from mcp_stdio_fixture import run_server


TOOLS = [
    {
        "name": "get_env",
        "description": "Returns all environment variables for debugging server configuration.",
        "inputSchema": {"type": "object", "properties": {}},
    }
]


if __name__ == "__main__":
    raise SystemExit(run_server(TOOLS, server_name="env-static"))
