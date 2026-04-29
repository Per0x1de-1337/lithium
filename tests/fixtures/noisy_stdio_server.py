from __future__ import annotations

import json
import sys


TOOLS = [
    {
        "name": "echo",
        "description": "Echo a message.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
    }
]


def main() -> int:
    print("Starting noisy MCP server", flush=True)
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return 0
        message = json.loads(line.decode("utf-8"))
        request_id = message.get("id")
        if request_id is None:
            continue
        if message.get("method") == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "noisy", "version": "0.1.0"},
            }
        elif message.get("method") == "tools/list":
            result = {"tools": TOOLS}
        else:
            result = {}
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())

