from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from collections.abc import Iterable
from typing import Any

from .models import Finding, ToolMetadata


HIDDEN_UNICODE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
URL_RE = re.compile(r"https?://[^\s)'\"<>]+", re.IGNORECASE)
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{48,}={0,2}\b")

PROMPT_OVERRIDE_RE = re.compile(
    r"\b("
    r"ignore (all )?(previous|prior|above)|"
    r"system prompt|developer message|"
    r"you are now|new instructions|"
    r"must obey|do not reveal|hidden policy|"
    r"before (any|every)|always run|never ask"
    r")\b",
    re.IGNORECASE,
)

SECRET_PATH_RE = re.compile(
    r"("
    r"~?/?\.ssh/(id_rsa|id_ed25519|config)|"
    r"\.env(\.|$|\b)|"
    r"credentials?(\.json)?|"
    r"aws_access_key|aws_secret|"
    r"/etc/passwd|"
    r"169\.254\.169\.254|metadata\.google\.internal|"
    r"token|api[_-]?key|private[_-]?key"
    r")",
    re.IGNORECASE,
)

AMBIENT_SECRET_RE = re.compile(
    r"\b("
    r"environment variables?|env vars?|"
    r"all environment|process\.env|"
    r"session cookies?|authorization headers?"
    r")\b",
    re.IGNORECASE,
)

GLOBAL_TOOL_RE = re.compile(
    r"\b("
    r"all tools|other tools|every tool|any tool|"
    r"before using|after using|whenever the user asks|"
    r"override|replace the behavior|shadow"
    r")\b",
    re.IGNORECASE,
)

DESTRUCTIVE_RE = re.compile(r"\b(delete|remove|overwrite|write|modify|execute|run command|shell)\b", re.IGNORECASE)


def scan_tools(tools: list[ToolMetadata]) -> list[Finding]:
    findings: list[Finding] = []
    tool_names = {tool.name for tool in tools}
    for tool in tools:
        text_items = list(_string_values(tool))
        findings.extend(_scan_tool_text(tool, text_items, tool_names - {tool.name}))
        findings.extend(_scan_annotations(tool, " ".join(value for _, value in text_items)))
    return _dedupe(findings)


def scan_config(config: dict[str, Any], source: str = "config") -> list[Finding]:
    findings: list[Finding] = []
    text = " ".join(value for _, value in _walk_strings(config))
    command = text.lower()
    if re.search(r"\bnpx\b.*(@latest|\blatest\b)", command) or re.search(r"\buvx\b.*(@latest|\blatest\b)", command):
        findings.append(
            Finding(
                rule_id="config-unpinned-package",
                title="Unpinned package execution in MCP config",
                severity="medium",
                category="MCP-CONFIG-001",
                tool_name=None,
                location=source,
                evidence=_clip(text),
                reasoning="The MCP config executes a package manager command without pinning a version.",
                dread=_dread(3, 4, 4, 3, 4),
            )
        )
    if re.search(r"[;&|`$()<>]", text):
        findings.append(
            Finding(
                rule_id="config-shell-metacharacters",
                title="Shell metacharacters in MCP config",
                severity="high",
                category="MCP-CONFIG-002",
                tool_name=None,
                location=source,
                evidence=_clip(text),
                reasoning="The MCP command or arguments contain shell metacharacters that can enable command injection if passed through a shell.",
                dread=_dread(4, 4, 4, 4, 4),
            )
        )
    if SECRET_PATH_RE.search(text):
        findings.append(
            Finding(
                rule_id="config-secret-reference",
                title="Sensitive file or secret reference in MCP config",
                severity="medium",
                category="MCP-CONFIG-003",
                tool_name=None,
                location=source,
                evidence=_clip(text),
                reasoning="The MCP configuration references secret-like paths or tokens.",
                dread=_dread(4, 4, 3, 3, 4),
            )
        )
    return findings


def _scan_tool_text(
    tool: ToolMetadata,
    text_items: list[tuple[str, str]],
    other_tool_names: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    combined = "\n".join(value for _, value in text_items)

    for location, value in text_items:
        hidden_chars = HIDDEN_UNICODE_RE.findall(value)
        if hidden_chars:
            findings.append(
                Finding(
                    rule_id="hidden-unicode",
                    title="Hidden or directional Unicode in tool metadata",
                    severity="high",
                    category="MCP-TOOL-POISONING",
                    tool_name=tool.name,
                    location=location,
                    evidence=_unicode_evidence(value),
                    reasoning="Invisible or bidirectional Unicode can hide instructions from reviewers while still being read by models.",
                    dread=_dread(4, 5, 4, 4, 5),
                )
            )

        if re.search(r"<!--.*?-->", value, re.DOTALL) or re.search(r"\s{80,}", value):
            findings.append(
                Finding(
                    rule_id="hidden-whitespace-or-comment",
                    title="Comment or whitespace-hidden metadata",
                    severity="medium",
                    category="MCP-TOOL-POISONING",
                    tool_name=tool.name,
                    location=location,
                    evidence=_clip(value),
                    reasoning="Long whitespace runs or comments can conceal instructions in descriptions and schemas.",
                    dread=_dread(3, 4, 3, 3, 4),
                )
            )

        if PROMPT_OVERRIDE_RE.search(value):
            findings.append(
                Finding(
                    rule_id="prompt-override",
                    title="Prompt override language in tool metadata",
                    severity="high",
                    category="MCP-TOOL-POISONING",
                    tool_name=tool.name,
                    location=location,
                    evidence=_clip(value),
                    reasoning="The metadata appears to instruct the agent outside the stated tool purpose.",
                    dread=_dread(4, 5, 4, 4, 4),
                )
            )

        if SECRET_PATH_RE.search(value):
            findings.append(
                Finding(
                    rule_id="secret-or-sensitive-reference",
                    title="Sensitive file, token, or credential reference",
                    severity="high",
                    category="MCP-EXFILTRATION",
                    tool_name=tool.name,
                    location=location,
                    evidence=_clip(value),
                    reasoning="Tool metadata references secret-like paths, tokens, or credential names.",
                    dread=_dread(5, 5, 4, 4, 5),
                )
            )

        if AMBIENT_SECRET_RE.search(value):
            findings.append(
                Finding(
                    rule_id="ambient-secret-exposure",
                    title="Tool metadata exposes ambient secrets or environment",
                    severity="high",
                    category="MCP-EXFILTRATION",
                    tool_name=tool.name,
                    location=location,
                    evidence=_clip(value),
                    reasoning="Tools that expose environment variables, cookies, or authorization headers can leak credentials without needing file access.",
                    dread=_dread(5, 5, 4, 4, 5),
                )
            )

        urls = URL_RE.findall(value)
        urls = [url for url in urls if not _benign_schema_url(location, url)]
        if urls:
            severity = "high" if any(_suspicious_url(url) for url in urls) else "medium"
            findings.append(
                Finding(
                    rule_id="metadata-url",
                    title="External URL embedded in tool metadata",
                    severity=severity,
                    category="MCP-EXFILTRATION",
                    tool_name=tool.name,
                    location=location,
                    evidence=", ".join(urls[:5]),
                    reasoning="URLs in tool metadata can be used as exfiltration endpoints or remote instruction sources.",
                    dread=_dread(4, 4, 4, 4, 4),
                )
            )

        for token in BASE64_RE.findall(value):
            if _looks_like_base64_payload(token):
                findings.append(
                    Finding(
                        rule_id="encoded-payload",
                        title="Encoded payload-like value in metadata",
                        severity="medium",
                        category="MCP-TOOL-POISONING",
                        tool_name=tool.name,
                        location=location,
                        evidence=_clip(token),
                        reasoning="Long base64-like strings in descriptions or schema text may hide instructions or endpoints.",
                        dread=_dread(3, 4, 3, 3, 4),
                    )
                )

    if len(combined) > 1800:
        findings.append(
            Finding(
                rule_id="oversized-description",
                title="Unusually large tool metadata",
                severity="low",
                category="MCP-TOOL-POISONING",
                tool_name=tool.name,
                location=f"tool:{tool.name}",
                evidence=f"{len(combined)} characters",
                reasoning="Large descriptions and schemas increase review difficulty and prompt-injection hiding space.",
                dread=_dread(2, 4, 2, 3, 4),
            )
        )

    if GLOBAL_TOOL_RE.search(combined):
        findings.append(
            Finding(
                rule_id="cross-tool-shadowing",
                title="Metadata tries to affect other tool behavior",
                severity="high",
                category="MCP-TOOL-SHADOWING",
                tool_name=tool.name,
                location=f"tool:{tool.name}",
                evidence=_clip(combined),
                reasoning="A tool description should describe that tool, not redefine global agent or other-tool behavior.",
                dread=_dread(4, 5, 4, 4, 4),
            )
        )

    lower_combined = combined.lower()
    for other_name in other_tool_names:
        if other_name and other_name.lower() in lower_combined:
            context = _context_for(lower_combined, other_name.lower())
            if "deprecated" in context and "instead" in context:
                continue
            if not re.search(r"\b(before|after|whenever|must|always|override|replace|call|invoke)\b", context):
                continue
            findings.append(
                Finding(
                    rule_id="named-tool-shadowing",
                    title="Metadata references another tool by name",
                    severity="medium",
                    category="MCP-TOOL-SHADOWING",
                    tool_name=tool.name,
                    location=f"tool:{tool.name}",
                    evidence=other_name,
                    reasoning="Cross-tool references can be used to shadow or override unrelated tool behavior.",
                    dread=_dread(3, 4, 3, 3, 4),
                )
            )

    return findings


def _scan_annotations(tool: ToolMetadata, combined_text: str) -> list[Finding]:
    findings: list[Finding] = []
    if tool.annotations.get("readOnlyHint") is True and DESTRUCTIVE_RE.search(combined_text):
        findings.append(
            Finding(
                rule_id="annotation-behavior-mismatch",
                title="Read-only annotation conflicts with destructive language",
                severity="medium",
                category="MCP-CONFUSED-DEPUTY",
                tool_name=tool.name,
                location=f"tool:{tool.name}.annotations",
                evidence=str(tool.annotations),
                reasoning="The tool claims to be read-only while its metadata suggests mutation or execution.",
                dread=_dread(3, 4, 3, 4, 4),
            )
        )
    return findings


def _string_values(tool: ToolMetadata) -> Iterable[tuple[str, str]]:
    yield f"tool:{tool.name}.description", tool.description
    for location, value in _walk_strings(tool.input_schema, f"tool:{tool.name}.inputSchema"):
        yield location, value
    for location, value in _walk_strings(tool.annotations, f"tool:{tool.name}.annotations"):
        yield location, value


def _walk_strings(value: Any, prefix: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield prefix, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_strings(item, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_strings(item, f"{prefix}[{index}]")


def _suspicious_url(url: str) -> bool:
    lower = url.lower()
    suspicious_terms = ["webhook", "hook", "paste", "requestbin", "ngrok", "discord", "slack"]
    if any(term in lower for term in suspicious_terms):
        return True
    host = re.sub(r"^https?://", "", lower).split("/", 1)[0].split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _benign_schema_url(location: str, url: str) -> bool:
    lower_url = url.lower().rstrip("#")
    lower_location = location.lower()
    return lower_location.endswith(".$schema") and lower_url in {
        "http://json-schema.org/draft-07/schema",
        "https://json-schema.org/draft-07/schema",
        "https://json-schema.org/draft/2020-12/schema",
    }


def _context_for(text: str, needle: str, radius: int = 120) -> str:
    index = text.find(needle)
    if index == -1:
        return ""
    start = max(index - radius, 0)
    end = min(index + len(needle) + radius, len(text))
    return text[start:end]


def _looks_like_base64_payload(token: str) -> bool:
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(decoded) < 24:
        return False
    printable = sum(32 <= byte <= 126 or byte in (9, 10, 13) for byte in decoded)
    return printable / max(len(decoded), 1) > 0.7


def _unicode_evidence(value: str) -> str:
    escaped = value.encode("unicode_escape").decode("ascii")
    return _clip(escaped)


def _clip(value: str, limit: int = 220) -> str:
    normalized = re.sub(r"\s+", " ", value).strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."


def _dread(damage: int, reproducibility: int, exploitability: int, affected_users: int, discoverability: int) -> dict[str, int]:
    return {
        "damage": damage,
        "reproducibility": reproducibility,
        "exploitability": exploitability,
        "affected_users": affected_users,
        "discoverability": discoverability,
    }


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.tool_name, finding.location, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
