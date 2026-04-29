from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .fetch import FetchError, fetch_from_config, fetch_http, fetch_stdio
from .interactive import run_interactive
from .inspector import interactive_inspect, render_overview
from .manifest import diff_manifests, generate_keypair, sign_manifest, verify_manifest_file
from .reports import render_report
from .rules import scan_config
from .scan import build_report
from .scoring import exit_code_for, score_findings, verdict_for


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command is None:
            if sys.stdin.isatty() and sys.stdout.isatty():
                return run_interactive()
            parser.print_help()
            return 0
        if args.command == "interactive":
            return run_interactive()
        if args.command == "scan":
            return _cmd_scan(args, ci_mode=False)
        if args.command == "inspect":
            return _cmd_inspect(args)
        if args.command == "ci":
            return _cmd_scan(args, ci_mode=True)
        if args.command == "keygen":
            return _cmd_keygen(args)
        if args.command == "verify":
            return _cmd_verify(args)
        if args.command == "diff":
            return _cmd_diff(args)
        if args.command == "rules":
            return _cmd_rules(args)
    except (FetchError, ValueError, RuntimeError, OSError) as exc:
        print(f"lithium: error: {exc}", file=sys.stderr)
        return 2
    parser.print_help()
    return 2


def _cmd_scan(args: argparse.Namespace, ci_mode: bool) -> int:
    config_findings = []
    fetched, config_findings = _fetch_for_scan(args)

    report = build_report(
        server=fetched.server,
        transport=fetched.transport,
        tools=fetched.tools,
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
    )
    if config_findings:
        findings = [*report.findings, *config_findings]
        risk_score = score_findings(findings)
        report = replace(report, findings=findings, risk_score=risk_score, verdict=verdict_for(findings, risk_score))

    rendered = render_report(report, args.format)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.manifest_out:
        if not args.sign_key:
            raise ValueError("--manifest-out requires --sign-key")
        manifest = sign_manifest(report, args.sign_key)
        Path(args.manifest_out).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if ci_mode or args.fail_on:
        return exit_code_for(report.verdict, args.fail_on or "high")
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    fetched, config_findings = _fetch_for_scan(args)
    report = build_report(server=fetched.server, transport=fetched.transport, tools=fetched.tools)
    if config_findings:
        findings = [*report.findings, *config_findings]
        risk_score = score_findings(findings)
        report = replace(report, findings=findings, risk_score=risk_score, verdict=verdict_for(findings, risk_score))

    if sys.stdin.isatty() and sys.stdout.isatty():
        interactive_inspect(report)
    else:
        print(render_overview(report))
    return 0


def _fetch_for_scan(args: argparse.Namespace):
    config_findings = []
    if args.stdio:
        fetched = fetch_stdio(args.stdio, timeout=args.timeout, ephemeral=not args.host_env)
    elif args.config:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        config_findings = scan_config(config, source=args.config)
        selected = _selected_server_config(config, args.server)
        if selected.get("command") and not args.allow_stdio:
            raise ValueError("config contains a stdio command; pass --allow-stdio to execute it for scanning")
        fetched = fetch_from_config(args.config, server_name=args.server, timeout=args.timeout, ephemeral=not args.host_env)
    elif args.target:
        if args.target.startswith(("http://", "https://")):
            fetched = fetch_http(args.target, timeout=args.timeout)
        else:
            raise ValueError("target must be an HTTP(S) endpoint, or use --stdio/--config")
    else:
        raise ValueError("provide a target, --stdio, or --config")
    return fetched, config_findings


def _cmd_keygen(args: argparse.Namespace) -> int:
    private_path = Path(args.private_key)
    public_path = Path(args.public_key)
    if not args.force and (private_path.exists() or public_path.exists()):
        raise ValueError("key file already exists; pass --force to overwrite")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    generate_keypair(str(private_path), str(public_path))
    print(f"created {private_path}")
    print(f"created {public_path}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    ok = verify_manifest_file(args.manifest, public_key_path=args.public_key)
    print("valid" if ok else "invalid")
    return 0 if ok else 1


def _cmd_diff(args: argparse.Namespace) -> int:
    diff = diff_manifests(args.old_manifest, args.new_manifest)
    print(json.dumps(diff, indent=2, sort_keys=True))
    if args.fail_on_change and diff["server_hash_changed"]:
        return 1
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = [
        "hidden-unicode",
        "hidden-whitespace-or-comment",
        "prompt-override",
        "secret-or-sensitive-reference",
        "ambient-secret-exposure",
        "metadata-url",
        "encoded-payload",
        "oversized-description",
        "cross-tool-shadowing",
        "named-tool-shadowing",
        "annotation-behavior-mismatch",
        "config-unpinned-package",
        "config-shell-metacharacters",
        "config-secret-reference",
        "llm-redteam-tool-poisoning",
    ]
    if args.format == "json":
        print(json.dumps({"rules": rules}, indent=2))
    else:
        for rule in rules:
            print(rule)
    return 0


def _selected_server_config(config: dict[str, object], server_name: str | None) -> dict[str, object]:
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict) or not servers:
        raise ValueError("config does not contain mcpServers")
    selected_name = server_name or next(iter(servers))
    selected = servers.get(selected_name)
    if not isinstance(selected, dict):
        raise ValueError(f"server not found in config: {selected_name}")
    return selected


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lithium",
        description="Interactive MCP trust scanner. Run `lithium` to start.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{interactive,scan,inspect,ci}")

    interactive = sub.add_parser("interactive", help="start the interactive CLI")
    interactive.set_defaults(command="interactive")

    scan = sub.add_parser("scan", help="fetch and scan MCP metadata")
    _add_scan_args(scan)

    inspect = sub.add_parser("inspect", help="browse MCP tools and metadata")
    _add_scan_args(inspect, inspect_mode=True)

    ci = sub.add_parser("ci", help="scan and exit non-zero when verdict meets --fail-on")
    _add_scan_args(ci, ci_mode=True)
    ci.set_defaults(fail_on="high")

    keygen = sub.add_parser("keygen", help=argparse.SUPPRESS)
    _hide_subcommand(sub, "keygen")
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-key", required=True)
    keygen.add_argument("--force", action="store_true")

    verify = sub.add_parser("verify", help=argparse.SUPPRESS)
    _hide_subcommand(sub, "verify")
    verify.add_argument("manifest")
    verify.add_argument("--public-key")

    diff = sub.add_parser("diff", help=argparse.SUPPRESS)
    _hide_subcommand(sub, "diff")
    diff.add_argument("old_manifest")
    diff.add_argument("new_manifest")
    diff.add_argument("--fail-on-change", action="store_true")

    rules = sub.add_parser("rules", help=argparse.SUPPRESS)
    _hide_subcommand(sub, "rules")
    rules.add_argument("--format", choices=["human", "json"], default="human")

    return parser


def _hide_subcommand(subparsers: argparse._SubParsersAction, name: str) -> None:
    subparsers._choices_actions = [action for action in subparsers._choices_actions if action.dest != name]


def _add_scan_args(parser: argparse.ArgumentParser, ci_mode: bool = False, inspect_mode: bool = False) -> None:
    advanced_help = argparse.SUPPRESS if not ci_mode else None
    parser.add_argument("target", nargs="?", help="HTTP(S) MCP JSON-RPC endpoint")
    parser.add_argument("--stdio", help="stdio MCP server command to execute")
    parser.add_argument("--config", help="Claude/Cursor-style MCP config file")
    parser.add_argument("--server", help="server name inside --config")
    parser.add_argument("--allow-stdio", action="store_true", help="allow executing stdio commands from --config")
    parser.add_argument(
        "--host-env",
        action="store_true",
        help=advanced_help or "run stdio commands with the host HOME/package caches instead of lithium's temporary sandbox",
    )
    if not inspect_mode:
        parser.add_argument("--format", choices=["human", "json", "sarif"], default="human")
        parser.add_argument("--output", help=advanced_help or "write report to a file")
        parser.add_argument("--manifest-out", help=advanced_help or "write signed trust manifest")
        parser.add_argument("--sign-key", help=advanced_help or "Ed25519 private key for --manifest-out")
        parser.add_argument("--fail-on", choices=["suspicious", "high", "high_risk", "critical"], help=None if ci_mode else argparse.SUPPRESS)
        parser.add_argument("--llm-provider", choices=["mock", "openai"], help=advanced_help)
        parser.add_argument("--llm-model", help=advanced_help)
    parser.add_argument("--timeout", type=float, default=30.0, help=advanced_help or "seconds to wait for MCP metadata")

    if inspect_mode:
        parser.set_defaults(format="human", output=None, manifest_out=None, sign_key=None, fail_on=None, llm_provider=None, llm_model=None)
