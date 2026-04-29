from __future__ import annotations

from datetime import datetime, timezone

from . import __version__
from .canonical import sha256_hex
from .llm import run_llm_red_team
from .models import Finding, ScanReport, ToolMetadata
from .rules import scan_tools
from .scoring import score_findings, verdict_for


def build_report(
    server: str,
    transport: str,
    tools: list[ToolMetadata],
    llm_provider: str | None = None,
    llm_model: str | None = None,
) -> ScanReport:
    findings: list[Finding] = scan_tools(tools)
    if llm_provider:
        findings.extend(run_llm_red_team(tools, provider=llm_provider, model=llm_model))

    tool_hashes = {tool.name: sha256_hex(tool.canonical_value()) for tool in sorted(tools, key=lambda item: item.name)}
    server_hash = sha256_hex({"tools": [tool.canonical_value() for tool in sorted(tools, key=lambda item: item.name)]})
    risk_score = score_findings(findings)
    verdict = verdict_for(findings, risk_score)

    return ScanReport(
        server=server,
        transport=transport,
        scanned_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        scanner_version=__version__,
        tools=tools,
        tool_hashes=tool_hashes,
        server_hash=server_hash,
        findings=findings,
        risk_score=risk_score,
        verdict=verdict,
    )

