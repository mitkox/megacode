# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Public repository URL references updated to
  `https://github.com/mitkox/megacode`.
- `--fast-mode` profile and `--overview-top-files` controls for small-context
  local model deployments.
- Progress heartbeat logging during long-running RLM attempts.
- Backward-compatible `limit_files` alias for `list_manifest`.
- `SKILL.md` for agent-based skill consumption (Claude Code/OpenCode style).
- `--search-rg-chunk-size` runtime control for chunked ripgrep-backed
  `search_pattern` scans.

### Changed

- Strengthened RLM instructions toward strict tool-only repository access.
- Improved manifest ranking to prioritize code-centric extensions.
- README and contribution docs updated to match latest CLI/runtime behavior.
- `search_pattern` now prefers a chunked `rg --json` backend (with automatic
  Python fallback), improving large-repo REPL scan speed.
- Fixed security signal regex word-boundary parsing so manifest signal ranking
  correctly detects risky tokens.
- Added an in-process LRU cache for `read_file` snippets to reduce repeated
  disk reads during iterative RLM analysis.
- Auto-normalized unqualified model IDs (for example `mitko`) to
  `openai/mitko` when using OpenAI-compatible API bases, preventing LiteLLM
  provider resolution failures.

## [0.2.0] - 2026-02-08

### Added

- GitHub open-source scaffolding:
  - `README.md`
  - `LICENSE` (MIT)
  - `CONTRIBUTING.md`
  - `SECURITY.md`
  - `CODE_OF_CONDUCT.md`
  - CI workflow and issue/PR templates
- Packaging improvements in `pyproject.toml`:
  - explicit build system
  - console script entrypoint
  - project metadata/classifiers/URLs
  - pytest configuration
- Basic unit tests for manifest/path/tool helpers.

### Changed

- Dependency floor updated to `dspy-ai>=3.1.3`.
