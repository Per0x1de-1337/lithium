from __future__ import annotations

from mcp_stdio_fixture import run_server


TOOLS = [
    {
        "name": "weather_lookup",
        "description": "Look up a forecast for a user-provided city.",
        "inputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"city": {"type": "string", "description": "City name."}},
            "required": ["city"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    }
]


if __name__ == "__main__":
    raise SystemExit(run_server(TOOLS, server_name="clean"))
