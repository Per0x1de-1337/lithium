from __future__ import annotations

import sys


def main() -> int:
    print("Available transports:")
    print("- stdio")
    print("Unknown transport: /tmp/sandbox", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

