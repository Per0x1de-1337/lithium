# lithium

`lithium` is a scanner for Model Context Protocol (MCP) servers. It fetches MCP metadata without calling tools, scans tool descriptions and schemas for prompt-injection and poisoning indicators, and emits deterministic reports.

## MVP scope

- HTTP JSON-RPC and stdio MCP metadata fetching
- Static rule engine for tool poisoning, exfiltration, hidden text, shadowing, and config risks
- Deterministic scoring and verdicts
- JSON, human, SARIF, and CI outputs
- Manifest verification and diffing
- Optional LLM red-team adapter with a mock provider for repeatable testing

## Development

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the CLI into the active virtualenv:

```bash
python -m pip install -e ".[dev]"
```

After that, these work from the project directory or any other directory while the venv is active:

```bash
lithium --help
lithium --version
lithium
```

The default command starts the interactive CLI. Choose a source, scan it, then browse tools, descriptions, schemas, annotations, hashes, and findings.

```bash
lithium scan \
  --stdio "uvx mcp-server-time" 
```

Review a server's tools and metadata directly:

```bash
lithium inspect --stdio "npx -y some-mcp-server"
```

`inspect` opens an interactive tool browser when run in a terminal. Use a tool number to show description, annotations, input schema, hash, and findings; use `/text` to filter; use `f` for all findings; use `q` to quit.

## Stdio isolation

`lithium scan --stdio ...` runs with a temporary `HOME` and temporary package-manager caches by default. This keeps `npx`, `uvx`, `pip`, `pnpm`, `yarn`, and `corepack` downloads inside a `lithium-stdio-*` temp directory that is deleted after the scan.

