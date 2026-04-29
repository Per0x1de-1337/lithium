from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


Severity = str

SEVERITY_ORDER: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_POINTS: dict[Severity, int] = {
    "info": 0,
    "low": 2,
    "medium": 5,
    "high": 10,
    "critical": 20,
}


@dataclass(frozen=True)
class ToolMetadata:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mcp(cls, value: dict[str, Any]) -> "ToolMetadata":
        return cls(
            name=str(value.get("name", "")),
            description=str(value.get("description", "") or ""),
            input_schema=dict(value.get("inputSchema") or value.get("input_schema") or {}),
            annotations=dict(value.get("annotations") or {}),
            raw=dict(value),
        )

    def canonical_value(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations,
        }


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    tool_name: str | None
    location: str
    evidence: str
    reasoning: str
    confidence: float = 1.0
    dread: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "tool_name": self.tool_name,
            "location": self.location,
            "evidence": self.evidence,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
        }
        if self.dread:
            data["dread"] = self.dread
            data["dread_score"] = round(sum(self.dread.values()) / len(self.dread), 2)
        return data


@dataclass(frozen=True)
class ScanReport:
    server: str
    transport: str
    scanned_at: str
    scanner_version: str
    tools: list[ToolMetadata]
    tool_hashes: dict[str, str]
    server_hash: str
    findings: list[Finding]
    risk_score: int
    verdict: str
    rule_pack_version: str = "static-rules-2026-05-29"

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "transport": self.transport,
            "scanned_at": self.scanned_at,
            "scanner_version": self.scanner_version,
            "rule_pack_version": self.rule_pack_version,
            "tool_count": len(self.tools),
            "tool_hashes": self.tool_hashes,
            "server_hash": self.server_hash,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "findings": [finding.to_dict() for finding in self.findings],
            "tools": [tool.canonical_value() for tool in self.tools],
        }

