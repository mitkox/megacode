# Security Audit (DSPy RLM)

RLM-based security auditing for large .NET repositories.

Open-sourced on GitHub: `https://github.com/mitkox/megacode`

This project uses `dspy.RLM` with a local Python REPL + host tools to avoid
loading all source files into the model context window. The model iteratively
uses indexed metadata and bounded file-access tools to find and explain
security issues.

## Repository

- GitHub: `https://github.com/mitkox/megacode`
- Issues: `https://github.com/mitkox/megacode/issues`

## Features

- Scales to large repositories via recursive/tool-based analysis.
- Indexes relevant source/config files into a ranked manifest.
- Exposes safe, bounded host tools to RLM:
  - `tool_help`
  - `list_manifest`
  - `search_pattern`
  - `read_file`
- `search_pattern` automatically uses ripgrep when available, with Python fallback.
- Produces:
  - Markdown report
  - JSON metadata
  - JSONL manifest

## Requirements

- Python 3.9+
- Deno (required by DSPy Python interpreter)
- ripgrep (`rg`) recommended for fastest REPL `search_pattern` scans on large repos
- OpenAI-compatible model endpoint (for example vLLM) reachable at
  `AUDIT_LM_API_BASE` (defaults to `http://localhost:8000/v1`)

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Quick Start

```bash
python audit.py --source-root ~/dev/PowerToys --verbose
```

Or via installed entrypoint:

```bash
security-audit --source-root ~/dev/PowerToys --verbose
```

Fast local profile (small-context vLLM):

```bash
security-audit \
  --source-root ~/dev/PowerToys \
  --fast-mode \
  --max-iterations 6 \
  --timeout-seconds 600
```

## Common Options

```bash
security-audit \
  --source-root ~/dev/PowerToys \
  --max-iterations 12 \
  --max-files 6000 \
  --overview-top-files 25 \
  --timeout-seconds 900 \
  --rlm-max-llm-calls 80 \
  --rlm-max-output-chars 25000
```

Important model options:

- `--lm-model` primary model
- `--sub-lm-model` sub-model for RLM internal LLM tool calls
- `--lm-api-base` OpenAI-compatible endpoint
- `--api-key` API key (if required by your endpoint)
- `--lm-max-tokens` response token ceiling per LM call

Tip: for OpenAI-compatible endpoints (including vLLM), passing `mitko` is supported;
the CLI auto-normalizes to `openai/mitko` for LiteLLM compatibility.

Useful runtime options:

- `--fast-mode` tighter defaults for faster/smaller-context runs
- `--verbose` / `--no-verbose` DSPy RLM iteration logs
- `--tool-max-lines`, `--tool-max-chars` bound file snippet payloads
- `--search-max-files`, `--search-max-matches` bound regex search breadth
- `--search-rg-chunk-size` files per `rg` batch for `search_pattern` backend
- `--overview-top-files` shrink/expand overview prompt size

## Output Files

By default:

- `security_audit_report.md`
- `security_audit_metadata.json`
- `security_audit_manifest.jsonl`

Change with:

- `--output-report`
- `--output-metadata`
- `--output-manifest`

## Troubleshooting

- No visible progress after "Starting audit attempt ...":
  - use `--verbose` to show RLM iteration logs
  - otherwise heartbeat logs print every ~20s while running
- If you set `AUDIT_VERBOSE=1` but pass `--no-verbose`, CLI flag wins.
- If output truncates:
  - lower `--rlm-max-output-chars`
  - lower `--max-iterations`
  - adjust `--lm-max-tokens` to fit backend constraints

## Development

```bash
ruff check .
pytest
python -m py_compile audit.py
```

## Security Notes

- This tool reports possible vulnerabilities and can produce false positives.
- Always validate findings before production changes.
- Do not commit sensitive audit outputs that may contain secrets.

## License

MIT (see `LICENSE`).
