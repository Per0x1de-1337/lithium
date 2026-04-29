from __future__ import annotations

from .models import Finding, SEVERITY_ORDER, SEVERITY_POINTS


def score_findings(findings: list[Finding]) -> int:
    total = 0
    for finding in findings:
        total += SEVERITY_POINTS.get(finding.severity, 0)
        if finding.confidence < 0.75:
            total -= 1
    return max(total, 0)


def verdict_for(findings: list[Finding], risk_score: int) -> str:
    max_severity = "info"
    for finding in findings:
        if SEVERITY_ORDER.get(finding.severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
            max_severity = finding.severity

    if max_severity == "critical":
        return "CRITICAL"
    if max_severity == "high" or risk_score >= 20:
        return "HIGH_RISK"
    if max_severity == "medium" or risk_score >= 5:
        return "SUSPICIOUS"
    return "CLEAN"


def exit_code_for(verdict: str, fail_on: str) -> int:
    order = {
        "clean": 0,
        "suspicious": 1,
        "high": 2,
        "high_risk": 2,
        "critical": 3,
    }
    normalized_verdict = verdict.lower()
    normalized_fail_on = fail_on.lower()
    return int(order.get(normalized_verdict, 0) >= order.get(normalized_fail_on, 2))
