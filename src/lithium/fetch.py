from __future__ import annotations

import json
import os
import re
import shlex
import signal
import select
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from json import JSONDecodeError
from typing import Any

import httpx

from .models import ToolMetadata


class FetchError(RuntimeError):
    pass


MAX_CAPTURE_BYTES = 8192
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass(frozen=True)
class FetchResult:
    server: str
    transport: str
    tools: list[ToolMetadata]


def fetch_http(endpoint: str, timeout: float = 10.0) -> FetchResult:
    client = httpx.Client(timeout=timeout)
    try:
        _json_rpc_http(client, endpoint, "initialize", _initialize_params(), request_id=1)
        # Initialized is a notification and some simple servers do not require it.
        _json_rpc_http(client, endpoint, "notifications/initialized", {}, request_id=None, tolerate_empty=True)
        tools_response = _json_rpc_http(client, endpoint, "tools/list", {}, request_id=2)
    finally:
        client.close()

    tools = _extract_tools(tools_response)
    return FetchResult(server=endpoint, transport="http", tools=tools)


def fetch_stdio(command: str, cwd: str | None = None, timeout: float = 10.0, ephemeral: bool = True) -> FetchResult:
    args = shlex.split(command.strip())
    if not args:
        raise FetchError("stdio command cannot be empty")
    if _looks_like_installer_command(args):
        raise FetchError(
            "the command looks like an MCP installer/helper, not an MCP server. "
            "lithium only scans commands that speak MCP over stdio. "
            "Use the actual server command from the MCP config it would install, for example "
            "`npx -y next-devtools-mcp@latest` for next-devtools."
        )

    with tempfile.TemporaryDirectory(prefix="lithium-stdio-", ignore_cleanup_errors=True) as temp_root:
        process = subprocess.Popen(
            args,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_safe_env(temp_root if ephemeral else None),
            start_new_session=True,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None

        reader = _MessageReader(
            process.stdout.fileno(),
            stderr_fd=process.stderr.fileno(),
            timeout=timeout,
            process=process,
        )
        try:
            _write_message(process.stdin, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": _initialize_params()})
            _read_response(reader, 1)
            _write_message(process.stdin, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            _write_message(process.stdin, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            tools_response = _read_response(reader, 2)
        except Exception:
            _kill_process_group(process)
            raise
        finally:
            _terminate(process)

    tools = _extract_tools(tools_response)
    return FetchResult(server=command, transport="stdio", tools=tools)


def fetch_from_config(path: str, server_name: str | None = None, timeout: float = 10.0, ephemeral: bool = True) -> FetchResult:
    config_path = Path(path)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict) or not servers:
        raise FetchError("config does not contain mcpServers")

    selected_name = server_name or next(iter(servers))
    if selected_name not in servers:
        raise FetchError(f"server not found in config: {selected_name}")
    selected = servers[selected_name]
    if not isinstance(selected, dict):
        raise FetchError(f"server config must be an object: {selected_name}")

    if selected.get("url"):
        result = fetch_http(str(selected["url"]), timeout=timeout)
        return FetchResult(server=f"{path}:{selected_name}", transport=result.transport, tools=result.tools)

    command = selected.get("command")
    args = selected.get("args") or []
    if not command:
        raise FetchError(f"server config has neither url nor command: {selected_name}")
    if not isinstance(args, list):
        raise FetchError(f"server args must be a list: {selected_name}")
    command_line = " ".join([shlex.quote(str(command)), *(shlex.quote(str(arg)) for arg in args)])
    result = fetch_stdio(command_line, cwd=str(config_path.parent), timeout=timeout, ephemeral=ephemeral)
    return FetchResult(server=f"{path}:{selected_name}", transport="stdio-config", tools=result.tools)


def _json_rpc_http(
    client: httpx.Client,
    endpoint: str,
    method: str,
    params: dict[str, Any],
    request_id: int | None,
    tolerate_empty: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        payload["id"] = request_id
    response = client.post(endpoint, json=payload, headers={"Accept": "application/json"})
    if tolerate_empty and response.status_code in {200, 202, 204} and not response.content:
        return {}
    if response.status_code >= 400:
        raise FetchError(f"HTTP MCP request failed for {method}: {response.status_code} {response.text[:200]}")
    if not response.content:
        return {}
    data = response.json()
    if "error" in data:
        raise FetchError(f"MCP error from {method}: {data['error']}")
    return dict(data.get("result") or {})


def _initialize_params() -> dict[str, Any]:
    return {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "lithium", "version": "0.1.0"},
    }


def _extract_tools(result: dict[str, Any]) -> list[ToolMetadata]:
    tools = result.get("tools", [])
    if not isinstance(tools, list):
        raise FetchError("tools/list response did not contain a tools list")
    return [ToolMetadata.from_mcp(tool) for tool in tools if isinstance(tool, dict)]


def _write_message(stdin: Any, message: dict[str, Any]) -> None:
    body = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
    stdin.write(body)
    stdin.flush()


def _read_response(reader: "_MessageReader", request_id: int) -> dict[str, Any]:
    deadline = time.monotonic() + reader.timeout
    while time.monotonic() < deadline:
        message = reader.read_message(deadline)
        if message.get("id") != request_id:
            continue
        if "error" in message:
            raise FetchError(f"MCP error for request {request_id}: {message['error']}")
        if "result" not in message:
            raise FetchError(_non_response_message(reader, message, request_id))
        return dict(message.get("result") or {})
    raise FetchError(f"timed out waiting for MCP response id {request_id}")


class _MessageReader:
    def __init__(
        self,
        fd: int,
        stderr_fd: int,
        timeout: float,
        process: subprocess.Popen[bytes] | None = None,
    ) -> None:
        self.fd = fd
        self.stderr_fd = stderr_fd
        self.timeout = timeout
        self.process = process
        self.buffer = bytearray()
        self.stderr_buffer = bytearray()
        self.stdout_noise = bytearray()
        self.stdout_closed = False
        self.stderr_closed = False

    def read_message(self, deadline: float) -> dict[str, Any]:
        while True:
            header_end = self.buffer.find(b"\r\n\r\n")
            newline = self.buffer.find(b"\n")
            if header_end != -1:
                header = bytes(self.buffer[:header_end]).decode("ascii", errors="replace")
                content_length = _parse_content_length(header)
                body_start = header_end + 4
                self._fill_until(body_start + content_length, deadline)
                body = bytes(self.buffer[body_start : body_start + content_length])
                del self.buffer[: body_start + content_length]
                return self._decode_json_message(body)
            if newline != -1 and not self.buffer.startswith(b"Content-Length:"):
                line = bytes(self.buffer[:newline]).strip()
                del self.buffer[: newline + 1]
                if line:
                    message = self._try_decode_json_line(line)
                    if message is not None:
                        return message
                continue
            self._read_more(deadline)

    def _decode_json_message(self, payload: bytes) -> dict[str, Any]:
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, JSONDecodeError) as exc:
            preview = payload.decode("utf-8", errors="replace").strip()
            if len(preview) > 300:
                preview = preview[:297] + "..."
            raise FetchError(_stdio_protocol_message(self.process, preview)) from exc
        if not isinstance(value, dict):
            raise FetchError("MCP stdio server returned a non-object JSON message")
        return dict(value)

    def _try_decode_json_line(self, payload: bytes) -> dict[str, Any] | None:
        stripped = payload.strip()
        if not stripped:
            return None
        if not stripped.startswith(b"{"):
            self._record_stdout_noise(stripped)
            return None
        return self._decode_json_message(stripped)

    def _record_stdout_noise(self, payload: bytes) -> None:
        if len(self.stdout_noise) >= MAX_CAPTURE_BYTES:
            return
        remaining = MAX_CAPTURE_BYTES - len(self.stdout_noise)
        if self.stdout_noise:
            self.stdout_noise.extend(b"\n")
        self.stdout_noise.extend(payload[:remaining])

    def _fill_until(self, size: int, deadline: float) -> None:
        while len(self.buffer) < size:
            self._read_more(deadline)

    def _read_more(self, deadline: float) -> None:
        remaining = max(deadline - time.monotonic(), 0.0)
        if remaining == 0.0:
            raise FetchError(self._diagnostic_message("timed out waiting for MCP stdio JSON-RPC response"))
        fds = []
        if not self.stdout_closed:
            fds.append(self.fd)
        if not self.stderr_closed:
            fds.append(self.stderr_fd)
        if not fds:
            raise FetchError(self._diagnostic_message("MCP stdio server closed stdout"))

        ready, _, _ = select.select(fds, [], [], remaining)
        if not ready:
            if self.process is not None and self.process.poll() is not None:
                raise FetchError(self._diagnostic_message("MCP stdio command exited before returning tools/list"))
            raise FetchError(self._diagnostic_message("timed out waiting for MCP stdio JSON-RPC response"))

        for fd in ready:
            chunk = os.read(fd, 65536)
            if fd == self.stderr_fd:
                if not chunk:
                    self.stderr_closed = True
                else:
                    self._append_stderr(chunk)
                continue

            if not chunk:
                self.stdout_closed = True
                if self.process is not None and self.process.poll() is not None:
                    raise FetchError(self._diagnostic_message("MCP stdio command exited before returning tools/list"))
                raise FetchError(self._diagnostic_message("MCP stdio server closed stdout"))
            self.buffer.extend(chunk)

    def _append_stderr(self, chunk: bytes) -> None:
        if len(self.stderr_buffer) >= MAX_CAPTURE_BYTES:
            return
        remaining = MAX_CAPTURE_BYTES - len(self.stderr_buffer)
        self.stderr_buffer.extend(chunk[:remaining])

    def _diagnostic_message(self, reason: str) -> str:
        parts = [reason]
        return_code = self.process.poll() if self.process is not None else None
        if return_code is not None:
            parts.append(f"exit_code: {return_code}")

        stdout = _decode_preview(bytes(self.stdout_noise))
        stderr = _decode_preview(bytes(self.stderr_buffer) or _read_available_stderr(self.process))
        if stdout:
            parts.append(f"stdout:\n{stdout}")
        if stderr:
            parts.append(f"stderr:\n{stderr}")
        if stdout or stderr or return_code is not None:
            parts.append(
                "hint: pass the actual MCP server command, not an installer/helper command. "
                "Use the command from the MCP config entry, for example "
                "`npx -y @modelcontextprotocol/server-everything`, not `npx add-mcp ...`."
            )
        return "\n".join(parts)


def _parse_content_length(header: str) -> int:
    for line in header.splitlines():
        name, _, value = line.partition(":")
        if name.lower() == "content-length":
            return int(value.strip())
    raise FetchError("MCP stdio message missing Content-Length")


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    _signal_process_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        process.wait(timeout=2)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    _signal_process_group(process, signal.SIGKILL)


def _signal_process_group(process: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return
    except OSError:
        try:
            if sig == signal.SIGTERM:
                process.terminate()
            else:
                process.kill()
        except OSError:
            return


def _closed_stdout_message(process: subprocess.Popen[bytes] | None) -> str:
    message = "MCP stdio server closed stdout"
    if process is None:
        return message
    stderr = _read_available_stderr(process)
    if stderr:
        return f"{message}: {stderr.decode('utf-8', errors='replace').strip()}"
    return message


def _stdio_protocol_message(process: subprocess.Popen[bytes] | None, stdout_preview: str) -> str:
    message = "MCP stdio server wrote non-JSON output to stdout"
    if stdout_preview:
        message += f": {stdout_preview}"
    stderr = _read_available_stderr(process)
    if stderr:
        message += f"\nstderr: {stderr.decode('utf-8', errors='replace').strip()}"
    return message


def _read_available_stderr(process: subprocess.Popen[bytes] | None) -> bytes:
    if process is None or process.stderr is None:
        return b""
    chunks: list[bytes] = []
    try:
        while True:
            ready, _, _ = select.select([process.stderr.fileno()], [], [], 0)
            if not ready:
                break
            chunk = os.read(process.stderr.fileno(), 8192)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(item) for item in chunks) >= MAX_CAPTURE_BYTES:
                break
    except OSError:
        return b""
    return b"".join(chunks)[:MAX_CAPTURE_BYTES]


def _decode_preview(value: bytes) -> str:
    preview = value.decode("utf-8", errors="replace").strip()
    preview = ANSI_ESCAPE_RE.sub("", preview)
    if len(preview) > 1200:
        preview = preview[:1197] + "..."
    return preview


def _looks_like_installer_command(args: list[str]) -> bool:
    normalized = [arg.lower() for arg in args]
    basenames = [Path(arg).name.lower() for arg in args]
    helper_names = {"add-mcp"}
    if basenames[0] in helper_names:
        return True
    if basenames[0] in {"npx", "pnpm", "yarn", "bun", "uvx"} and len(basenames) > 1:
        package_index = 1
        while package_index < len(normalized) and normalized[package_index].startswith("-"):
            package_index += 1
        if package_index >= len(normalized):
            return False
        package = normalized[package_index]
        command = normalized[package_index + 1] if package_index + 1 < len(normalized) else ""
        if Path(package).name.lower() in helper_names:
            return True
        if package in {"@smithery/cli", "smithery"} and command in {"install", "list", "search"}:
            return True
    if basenames[0] == "smithery" and len(normalized) > 1 and normalized[1] in {"install", "list", "search"}:
        return True
    return False


def _non_response_message(reader: "_MessageReader", message: dict[str, Any], request_id: int) -> str:
    method = message.get("method")
    if method:
        reason = f"MCP stdio command echoed or emitted a JSON-RPC request instead of a response for id {request_id}"
    else:
        reason = f"MCP stdio command returned JSON without a result for id {request_id}"
    return reader._diagnostic_message(reason)


def _safe_env(ephemeral_root: str | None = None) -> dict[str, str]:
    keep = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    }
    env = {key: value for key, value in os.environ.items() if key in keep}
    if ephemeral_root is None:
        return env

    root = Path(ephemeral_root)
    home = root / "home"
    tmp = root / "tmp"
    cache = root / "cache"
    for path in [
        home,
        tmp,
        cache,
        root / "npm-cache",
        root / "uv-cache",
        root / "uv-tools",
        root / "pip-cache",
        root / "pnpm-home",
        root / "yarn-cache",
        root / "corepack-home",
        root / "bun-install",
        root / "bun-cache",
    ]:
        path.mkdir(parents=True, exist_ok=True)

    env.update(
        {
            "HOME": str(home),
            "TMPDIR": str(tmp),
            "XDG_CACHE_HOME": str(cache),
            "npm_config_cache": str(root / "npm-cache"),
            "npm_config_userconfig": str(home / ".npmrc"),
            "NPM_CONFIG_CACHE": str(root / "npm-cache"),
            "NPM_CONFIG_USERCONFIG": str(home / ".npmrc"),
            "UV_CACHE_DIR": str(root / "uv-cache"),
            "UV_TOOL_DIR": str(root / "uv-tools"),
            "PIP_CACHE_DIR": str(root / "pip-cache"),
            "PNPM_HOME": str(root / "pnpm-home"),
            "YARN_CACHE_FOLDER": str(root / "yarn-cache"),
            "COREPACK_HOME": str(root / "corepack-home"),
            "BUN_INSTALL": str(root / "bun-install"),
            "BUN_CACHE_DIR": str(root / "bun-cache"),
        }
    )
    return env
