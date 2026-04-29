from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path("/home/peroxide/AIAgents/agent-venv/bin/python3")
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}


def fixture_command(name: str) -> str:
    return f"{PYTHON} {ROOT / 'tests/fixtures' / name}"


def run_cli(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(PYTHON), "-m", "lithium", *args],
        cwd=ROOT,
        env=ENV,
        text=True,
        capture_output=True,
        timeout=20,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"command failed: {result.args}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result


def run_cli_input(input_text: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(PYTHON), "-m", "lithium", *args],
        cwd=ROOT,
        env=ENV,
        text=True,
        input=input_text,
        capture_output=True,
        timeout=20,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"command failed: {result.args}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result


def test_clean_stdio_server_is_clean() -> None:
    result = run_cli("scan", "--stdio", fixture_command("clean_stdio_server.py"), "--format", "json")
    data = json.loads(result.stdout)
    assert data["verdict"] == "CLEAN"
    assert data["findings"] == []


def test_poisoned_stdio_server_flags_static_and_llm() -> None:
    result = run_cli("scan", "--stdio", fixture_command("stdio_server.py"), "--llm-provider", "mock", "--format", "json")
    data = json.loads(result.stdout)
    rule_ids = {finding["rule_id"] for finding in data["findings"]}
    assert data["verdict"] in {"HIGH_RISK", "CRITICAL"}
    assert "secret-or-sensitive-reference" in rule_ids
    assert "metadata-url" in rule_ids
    assert "llm-redteam-tool-poisoning" in rule_ids


def test_json_schema_url_is_not_exfiltration_noise() -> None:
    result = run_cli("scan", "--stdio", fixture_command("clean_stdio_server.py"), "--format", "json")
    data = json.loads(result.stdout)
    assert all(finding["rule_id"] != "metadata-url" for finding in data["findings"])


def test_ambient_environment_exposure_is_flagged() -> None:
    result = run_cli("scan", "--stdio", fixture_command("env_static_stdio_server.py"), "--format", "json")
    data = json.loads(result.stdout)
    assert any(finding["rule_id"] == "ambient-secret-exposure" for finding in data["findings"])


def test_stdio_mcp_scan_end_to_end() -> None:
    result = run_cli("scan", "--stdio", fixture_command("stdio_server.py"), "--format", "json")
    data = json.loads(result.stdout)
    assert data["transport"] == "stdio"
    assert data["tool_count"] == 1
    assert data["verdict"] in {"HIGH_RISK", "CRITICAL"}


def test_stdio_tolerates_startup_stdout_noise() -> None:
    result = run_cli("scan", "--stdio", fixture_command("noisy_stdio_server.py"), "--format", "json")
    data = json.loads(result.stdout)
    assert data["transport"] == "stdio"
    assert data["tool_count"] == 1
    assert data["verdict"] == "CLEAN"


def test_stdio_uses_ephemeral_package_caches_by_default() -> None:
    result = run_cli("scan", "--stdio", fixture_command("env_reporting_stdio_server.py"), "--format", "json")
    data = json.loads(result.stdout)
    description = data["tools"][0]["description"]
    assert "/home/peroxide" not in description
    home = re.search(r"HOME=([^;]+)", description)
    npm_cache = re.search(r"npm_config_cache=([^;]+)", description)
    uv_cache = re.search(r"UV_CACHE_DIR=([^;]+)", description)
    assert home and npm_cache and uv_cache
    assert "lithium-stdio-" in home.group(1)
    assert "lithium-stdio-" in npm_cache.group(1)
    assert "lithium-stdio-" in uv_cache.group(1)
    assert not Path(home.group(1)).exists()


def test_stdio_host_env_escape_hatch() -> None:
    result = run_cli("scan", "--stdio", fixture_command("env_reporting_stdio_server.py"), "--host-env", "--format", "json")
    data = json.loads(result.stdout)
    description = data["tools"][0]["description"]
    assert "HOME=/home/peroxide" in description


def test_http_mcp_scan_end_to_end() -> None:
    process = subprocess.Popen(
        [str(PYTHON), str(ROOT / "tests/fixtures/http_server.py")],
        cwd=ROOT,
        env=ENV,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    try:
        port = process.stdout.readline().strip()
        result = run_cli("scan", f"http://127.0.0.1:{port}", "--format", "json")
    finally:
        process.terminate()
        process.wait(timeout=5)
    data = json.loads(result.stdout)
    assert data["transport"] == "http"
    assert data["tool_count"] == 1
    assert any(finding["rule_id"] == "hidden-unicode" for finding in data["findings"])


def test_manifest_sign_verify_and_diff(tmp_path: Path) -> None:
    private_key = tmp_path / "key.pem"
    public_key = tmp_path / "key.pub"
    manifest_clean = tmp_path / "clean.manifest.json"
    manifest_poisoned = tmp_path / "poisoned.manifest.json"

    run_cli("keygen", "--private-key", str(private_key), "--public-key", str(public_key))
    run_cli("scan", "--stdio", fixture_command("clean_stdio_server.py"), "--manifest-out", str(manifest_clean), "--sign-key", str(private_key))
    run_cli("scan", "--stdio", fixture_command("stdio_server.py"), "--manifest-out", str(manifest_poisoned), "--sign-key", str(private_key))

    verify = run_cli("verify", str(manifest_clean), "--public-key", str(public_key))
    assert verify.stdout.strip() == "valid"

    diff = run_cli("diff", str(manifest_clean), str(manifest_poisoned))
    data = json.loads(diff.stdout)
    assert data["server_hash_changed"] is True
    assert "security_check" in data["added_tools"]


def test_ci_gate_fails_on_high_risk() -> None:
    result = run_cli("ci", "--stdio", fixture_command("stdio_server.py"), "--format", "json", check=False)
    assert result.returncode == 1
    assert json.loads(result.stdout)["verdict"] in {"HIGH_RISK", "CRITICAL"}


def test_inspect_prints_tool_metadata_overview() -> None:
    result = run_cli("inspect", "--stdio", fixture_command("stdio_server.py"))
    assert "lithium inspect:" in result.stdout
    assert "security_check" in result.stdout
    assert "findings:" in result.stdout


def test_scan_help_keeps_advanced_flags_out_of_default_view() -> None:
    result = run_cli("scan", "--help")
    assert "--stdio" in result.stdout
    assert "--config" in result.stdout
    assert "--fixture" not in result.stdout
    assert "--manifest-out" not in result.stdout
    assert "--llm-provider" not in result.stdout


def test_top_level_help_is_not_overwhelming_when_non_interactive() -> None:
    result = run_cli()
    assert "interactive" in result.stdout
    assert "scan" in result.stdout
    assert "inspect" in result.stdout
    assert "keygen" not in result.stdout
    assert "manifest" not in result.stdout


def test_top_level_version() -> None:
    result = run_cli("--version")
    assert result.stdout.strip().startswith("lithium ")


def test_interactive_stdio_flow() -> None:
    result = run_cli_input(f"1\n{fixture_command('stdio_server.py')}\n30\nn\nn\n", "interactive")
    assert "Choose a source" in result.stdout
    assert "lithium inspect:" in result.stdout
    assert "security_check" in result.stdout


def test_interactive_can_open_tool_browser() -> None:
    result = run_cli_input(f"1\n{fixture_command('clean_stdio_server.py')}\n30\ny\n1\nq\nn\n", "interactive")
    assert "Tool: weather_lookup" in result.stdout
    assert "Input schema:" in result.stdout


def test_config_requires_explicit_stdio_execution(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fixture": {
                        "command": str(PYTHON),
                        "args": [str(ROOT / "tests/fixtures/stdio_server.py")],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = run_cli("scan", "--config", str(config), check=False)
    assert result.returncode == 2
    assert "--allow-stdio" in result.stderr

    allowed = run_cli("scan", "--config", str(config), "--allow-stdio", "--format", "json")
    assert json.loads(allowed.stdout)["transport"] == "stdio-config"


def test_stdio_non_json_stdout_reports_server_output() -> None:
    result = run_cli("scan", "--stdio", fixture_command("bad_stdout_server.py"), check=False)
    assert result.returncode == 2
    assert "exited before returning tools/list" in result.stderr
    assert "Available transports" in result.stderr
    assert "Unknown transport" in result.stderr
    assert "actual MCP server command" in result.stderr


def test_stdio_refuses_known_installer_command() -> None:
    result = run_cli("scan", "--stdio", "npx add-mcp next-devtools-mcp@latest", check=False)
    assert result.returncode == 2
    assert "installer/helper" in result.stderr
    assert "npx -y next-devtools-mcp@latest" in result.stderr


def test_stdio_refuses_smithery_installer_command() -> None:
    result = run_cli("scan", "--stdio", "npx @smithery/cli install e2b", check=False)
    assert result.returncode == 2
    assert "installer/helper" in result.stderr


def test_stdio_echoed_request_reports_not_mcp_response() -> None:
    result = run_cli("scan", "--stdio", fixture_command("echo_request_server.py"), check=False)
    assert result.returncode == 2
    assert "instead of a response" in result.stderr


@pytest.mark.parametrize("fmt", ["human", "json", "sarif"])
def test_report_formats(fmt: str) -> None:
    result = run_cli("scan", "--stdio", fixture_command("stdio_server.py"), "--format", fmt)
    assert result.stdout
