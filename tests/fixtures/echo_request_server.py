from __future__ import annotations

import sys


def main() -> int:
    line = sys.stdin.buffer.readline()
    if line:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

