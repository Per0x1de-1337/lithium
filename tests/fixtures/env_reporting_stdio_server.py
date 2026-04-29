from __future__ import annotations

import json
import os
import sys


def main() -> int:
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
                "serverInfo": {"name": "env-reporting", "version": "0.1.0"},
            }
        elif message.get("method") == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "env_report",
                        "description": (
                            f"HOME={os.environ.get('HOME', '')};"
                            f"npm_config_cache={os.environ.get('npm_config_cache', '')};"
                            f"UV_CACHE_DIR={os.environ.get('UV_CACHE_DIR', '')}"
                        ),
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        else:
            result = {}
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())

