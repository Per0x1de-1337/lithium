from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from .fetch import fetch_from_config, fetch_http, fetch_stdio
from .inspector import interactive_inspect, render_overview
from .rules import scan_config
from .scan import build_report
from .scoring import score_findings, verdict_for


def run_interactive() -> int:
    print("lithium")
    print("Read-only MCP trust scanner")
    print("")
    while True:
        print("Choose a source:")
        print("  1. stdio command")
        print("  2. HTTP endpoint")
        print("  3. MCP config file")
        print("  q. quit")
        choice = _prompt("source").lower()
        if choice in {"q", "quit", "exit"}:
            return 0
        try:
            report = _scan_choice(choice)
        except KeyboardInterrupt:
            print()
            return 130
        except Exception as exc:
            print(f"error: {exc}")
            print("")
            continue

        print("")
        print(render_overview(report))
        if _prompt_yes_no("Open tool browser?", default=True):
            interactive_inspect(report)
        if not _prompt_yes_no("Scan another server?", default=False):
            return 0
        print("")


def _scan_choice(choice: str):
    if choice in {"1", "stdio", "s"}:
        command = _required("stdio command")
        timeout = _timeout()
        fetched = fetch_stdio(command, timeout=timeout, ephemeral=True)
        return build_report(server=fetched.server, transport=fetched.transport, tools=fetched.tools)

    if choice in {"2", "http", "url"}:
        endpoint = _required("HTTP endpoint")
        timeout = _timeout()
        fetched = fetch_http(endpoint, timeout=timeout)
        return build_report(server=fetched.server, transport=fetched.transport, tools=fetched.tools)

    if choice in {"3", "config", "c"}:
        path = _required("config path")
        server = _prompt("server name (blank = first)").strip() or None
        config = json.loads(Path(path).read_text(encoding="utf-8"))
        findings = scan_config(config, source=path)
        fetched = fetch_from_config(path, server_name=server, timeout=_timeout(), ephemeral=True)
        report = build_report(server=fetched.server, transport=fetched.transport, tools=fetched.tools)
        if findings:
            all_findings = [*report.findings, *findings]
            risk_score = score_findings(all_findings)
            report = replace(report, findings=all_findings, risk_score=risk_score, verdict=verdict_for(all_findings, risk_score))
        return report

    raise ValueError("choose 1, 2, 3, or q")


def _prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{label}{suffix}> ").strip()
    return value if value else (default or "")


def _required(label: str) -> str:
    value = _prompt(label)
    if not value:
        raise ValueError(f"{label} is required")
    return value


def _timeout() -> float:
    raw = _prompt("timeout seconds", default="30")
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError("timeout must be a number") from exc
    if value <= 0:
        raise ValueError("timeout must be positive")
    return value


def _prompt_yes_no(label: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    value = input(f"{label} [{hint}] ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}
