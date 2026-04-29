from __future__ import annotations

import json
import shutil
from textwrap import fill

from .models import Finding, ScanReport, ToolMetadata


def render_overview(report: ScanReport) -> str:
    lines = [
        f"lithium inspect: {report.server}",
        f"transport: {report.transport}",
        f"verdict: {report.verdict}  risk_score: {report.risk_score}",
        f"tools: {len(report.tools)}",
        "",
        "Tools:",
    ]
    findings_by_tool = _findings_by_tool(report.findings)
    width = shutil.get_terminal_size((100, 24)).columns
    for index, tool in enumerate(report.tools, 1):
        severities = sorted({finding.severity for finding in findings_by_tool.get(tool.name, [])})
        suffix = f"  findings: {', '.join(severities)}" if severities else ""
        summary = _first_line(tool.description) or "(no description)"
        lines.append(f"{index:>2}. {tool.name}{suffix}")
        lines.append("    " + _clip(summary, max(48, width - 8)))
    lines.extend(
        [
            "",
            "Interactive commands: number = details, f = findings, /text = filter, q = quit",
        ]
    )
    return "\n".join(lines)


def interactive_inspect(report: ScanReport) -> None:
    filtered = report.tools
    print(render_overview(report))
    while True:
        try:
            command = input("lithium> ").strip()
        except EOFError:
            print()
            return
        if command in {"q", "quit", "exit"}:
            return
        if command in {"", "l", "list"}:
            print(_render_tool_list(filtered, report.findings))
            continue
        if command == "f":
            print(render_findings(report.findings))
            continue
        if command.startswith("/"):
            query = command[1:].strip().lower()
            filtered = [
                tool
                for tool in report.tools
                if query in tool.name.lower()
                or query in tool.description.lower()
                or query in json.dumps(tool.input_schema, sort_keys=True).lower()
            ]
            print(_render_tool_list(filtered, report.findings))
            continue
        if command.isdigit():
            index = int(command)
            if 1 <= index <= len(filtered):
                print(render_tool_detail(filtered[index - 1], report))
            else:
                print("No tool at that number.")
            continue
        print("Commands: number, f, /text, list, q")


def render_tool_detail(tool: ToolMetadata, report: ScanReport) -> str:
    tool_findings = [finding for finding in report.findings if finding.tool_name == tool.name]
    lines = [
        f"Tool: {tool.name}",
        f"hash: {report.tool_hashes.get(tool.name, '(missing)')}",
        "",
        "Description:",
        _wrap(tool.description or "(no description)"),
        "",
        "Annotations:",
        _json_block(tool.annotations or {}),
        "",
        "Input schema:",
        _json_block(tool.input_schema or {}),
    ]
    if tool_findings:
        lines.extend(["", "Findings:", render_findings(tool_findings)])
    return "\n".join(lines)


def render_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    lines: list[str] = []
    for finding in findings:
        subject = finding.tool_name or "server"
        lines.append(f"- [{finding.severity.upper()}] {finding.rule_id} on {subject}")
        lines.append(f"  {finding.title}")
        lines.append(f"  evidence: {finding.evidence}")
    return "\n".join(lines)


def _render_tool_list(tools: list[ToolMetadata], findings: list[Finding]) -> str:
    fake_report = type("_Report", (), {"findings": findings, "tools": tools})()
    findings_by_tool = _findings_by_tool(fake_report.findings)
    lines = [f"Tools ({len(tools)}):"]
    for index, tool in enumerate(tools, 1):
        count = len(findings_by_tool.get(tool.name, []))
        suffix = f"  findings: {count}" if count else ""
        lines.append(f"{index:>2}. {tool.name}{suffix}")
    return "\n".join(lines)


def _findings_by_tool(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.tool_name:
            grouped.setdefault(finding.tool_name, []).append(finding)
    return grouped


def _wrap(value: str) -> str:
    width = shutil.get_terminal_size((100, 24)).columns
    return fill(value, width=max(48, width - 2))


def _json_block(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def _first_line(value: str) -> str:
    return value.strip().splitlines()[0].strip() if value.strip() else ""


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."

