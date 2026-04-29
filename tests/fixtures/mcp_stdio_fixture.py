from __future__ import annotations

import json
import sys
from typing import Any


def run_server(tools: list[dict[str, Any]], server_name: str = "test") -> int:
    while True:
        message = read_message()
        if message is None:
            return 0
        request_id = message.get("id")
        if request_id is None:
            continue
        method = message.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": server_name, "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": tools}
        else:
            result = {}
        write_message({"jsonrpc": "2.0", "id": request_id, "result": result})


def read_message() -> dict[str, Any] | None:
    line = sys.stdin.buffer.readline()
    if not line:
        return None
    return dict(json.loads(line.decode("utf-8")))


def write_message(message: dict[str, Any]) -> None:
    print(json.dumps(message, separators=(",", ":")), flush=True)
