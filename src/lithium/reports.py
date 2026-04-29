from __future__ import annotations

import json
from typing import Any

from .models import ScanReport, SEVERITY_ORDER


def render_report(report: ScanReport, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if fmt == "sarif":
        return json.dumps(to_sarif(report), indent=2, sort_keys=True)
    if fmt == "human":
        return to_human(report)
    raise ValueError(f"unknown format: {fmt}")


def to_human(report: ScanReport) -> str:
    lines = [
        f"lithium scan: {report.server}",
        f"transport: {report.transport}",
        f"tools: {len(report.tools)}",
        f"verdict: {report.verdict}",
        f"risk_score: {report.risk_score}",
        f"server_hash: {report.server_hash}",
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("Findings:")
    for finding in sorted(report.findings, key=lambda item: SEVERITY_ORDER.get(item.severity, 0), reverse=True):
        subject = finding.tool_name or "server"
        lines.append(f"- [{finding.severity.upper()}] {finding.rule_id} on {subject}")
        lines.append(f"  {finding.title}")
        lines.append(f"  evidence: {finding.evidence}")
    return "\n".join(lines)


def to_sarif(report: ScanReport) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.reasoning},
            "properties": {"category": finding.category, "severity": finding.severity},
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": f"{finding.title}: {finding.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.location},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": finding.to_dict(),
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lithium",
                        "version": report.scanner_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "server": report.server,
                    "verdict": report.verdict,
                    "risk_score": report.risk_score,
                    "server_hash": report.server_hash,
                },
            }
        ],
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"

