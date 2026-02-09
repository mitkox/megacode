import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

import dspy


DEFAULT_SOURCE_ROOT = Path(
    os.path.expanduser(os.getenv("AUDIT_SOURCE_ROOT", "~/dev/PowerToys/"))
)
DEFAULT_MAX_ITERATIONS = int(os.getenv("AUDIT_MAX_ITERATIONS", "12"))
DEFAULT_MAX_FILES = int(os.getenv("AUDIT_MAX_FILES", "6000"))
DEFAULT_MAX_FILE_BYTES = int(os.getenv("AUDIT_MAX_FILE_BYTES", "200000"))
DEFAULT_LM_MODEL = os.getenv("AUDIT_LM_MODEL", "openai/mitko")
DEFAULT_SUB_LM_MODEL = os.getenv("AUDIT_SUB_LM_MODEL", DEFAULT_LM_MODEL)
DEFAULT_LM_API_BASE = os.getenv("AUDIT_LM_API_BASE", "http://localhost:8000/v1")
DEFAULT_LM_MAX_TOKENS = int(os.getenv("AUDIT_LM_MAX_TOKENS", "8192"))
DEFAULT_VERBOSE = os.getenv("AUDIT_VERBOSE", "0") == "1"
DEFAULT_RETRIES = int(os.getenv("AUDIT_RETRIES", "2"))
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("AUDIT_TIMEOUT_SECONDS", "900"))
DEFAULT_BACKOFF_SECONDS = float(os.getenv("AUDIT_BACKOFF_SECONDS", "2.0"))
DEFAULT_SKIP_HIDDEN_DIRS = os.getenv("AUDIT_SKIP_HIDDEN_DIRS", "1") != "0"
DEFAULT_RLM_MAX_LLM_CALLS = int(os.getenv("AUDIT_RLM_MAX_LLM_CALLS", "80"))
DEFAULT_RLM_MAX_OUTPUT_CHARS = int(
    os.getenv("AUDIT_RLM_MAX_OUTPUT_CHARS", "25000")
)
DEFAULT_TOOL_MAX_LINES = int(os.getenv("AUDIT_TOOL_MAX_LINES", "300"))
DEFAULT_TOOL_MAX_CHARS = int(os.getenv("AUDIT_TOOL_MAX_CHARS", "30000"))
DEFAULT_SEARCH_MAX_FILES = int(os.getenv("AUDIT_SEARCH_MAX_FILES", "1200"))
DEFAULT_SEARCH_MAX_MATCHES = int(os.getenv("AUDIT_SEARCH_MAX_MATCHES", "300"))
DEFAULT_SEARCH_RG_CHUNK_SIZE = int(os.getenv("AUDIT_SEARCH_RG_CHUNK_SIZE", "64"))
DEFAULT_OVERVIEW_TOP_FILES = int(os.getenv("AUDIT_OVERVIEW_TOP_FILES", "25"))
DEFAULT_API_KEY = os.getenv("AUDIT_API_KEY", "not-needed")
DEFAULT_OUTPUT_REPORT = Path(
    os.path.expanduser(
        os.getenv("AUDIT_OUTPUT_REPORT", "security_audit_report.md")
    )
)
DEFAULT_OUTPUT_METADATA = Path(
    os.path.expanduser(
        os.getenv("AUDIT_OUTPUT_METADATA", "security_audit_metadata.json")
    )
)
DEFAULT_OUTPUT_MANIFEST = Path(
    os.path.expanduser(
        os.getenv("AUDIT_OUTPUT_MANIFEST", "security_audit_manifest.jsonl")
    )
)

# Keep high-signal source/config files; skip binaries and build artifacts.
INCLUDE_EXTENSIONS = {
    ".cs",
    ".cshtml",
    ".csproj",
    ".fs",
    ".fsproj",
    ".json",
    ".props",
    ".razor",
    ".resx",
    ".sln",
    ".targets",
    ".vb",
    ".vbproj",
    ".xml",
    ".xaml",
    ".yml",
    ".yaml",
}
INCLUDE_FILENAMES = {
    "appsettings.json",
    "appsettings.development.json",
    "nuget.config",
    "packages.config",
    "web.config",
    "Directory.Build.props",
    "Directory.Build.targets",
    "global.json",
    "Dockerfile",
}
SKIP_DIRS = {
    ".git",
    ".github",
    ".vscode",
    ".vs",
    "bin",
    "obj",
    "node_modules",
    "packages",
    "artifacts",
    "build",
    "dist",
    "out",
}

SECURITY_PATH_HINTS = (
    "auth",
    "security",
    "signin",
    "login",
    "token",
    "jwt",
    "controller",
    "middleware",
    "upload",
    "admin",
    "api",
    "http",
    "config",
    "settings",
    "crypto",
    "cert",
)
SECURITY_SIGNAL_PATTERN = re.compile(
    r"(?i)\b("
    r"fromsqlraw|fromsqlinterpolated|executesqlraw|sqlcommand|commandtext|"
    r"process\\.start|ldap|binaryformatter|typenamehandling|deserialize|"
    r"html\\.raw|allowanonymous|authorize|jwt|tokenvalidation|"
    r"password|api[_-]?key|secret|connectionstring|"
    r"md5|sha1|aes|rsa|certificatevalidationcallback|"
    r"httpclient|webrequest|mappath|path\\.combine|upload"
    r")\b"
)
EXTENSION_PRIORITY = {
    ".cs": 10,
    ".cshtml": 9,
    ".razor": 9,
    ".vb": 8,
    ".fs": 8,
    ".json": 5,
    ".xml": 4,
    ".xaml": 4,
    ".yml": 3,
    ".yaml": 3,
    ".config": 2,
    ".resx": 1,
}


def _is_audit_file(path: Path) -> bool:
    if path.name in INCLUDE_FILENAMES:
        return True
    return path.suffix.lower() in INCLUDE_EXTENSIONS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a .NET security audit using DSPy RLM and local REPL access."
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=DEFAULT_SOURCE_ROOT,
        help="Repository root to audit.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=DEFAULT_MAX_ITERATIONS,
        help="Maximum RLM iterations.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_FILES,
        help="Maximum source files indexed in the manifest.",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="Ignore files larger than this byte limit.",
    )
    parser.add_argument(
        "--rlm-max-llm-calls",
        type=int,
        default=DEFAULT_RLM_MAX_LLM_CALLS,
        help="Maximum sub-LLM calls allowed by RLM tools.",
    )
    parser.add_argument(
        "--rlm-max-output-chars",
        type=int,
        default=DEFAULT_RLM_MAX_OUTPUT_CHARS,
        help="Maximum chars from REPL output kept per step.",
    )
    parser.add_argument(
        "--tool-max-lines",
        type=int,
        default=DEFAULT_TOOL_MAX_LINES,
        help="Default maximum lines returned by read_file tool.",
    )
    parser.add_argument(
        "--tool-max-chars",
        type=int,
        default=DEFAULT_TOOL_MAX_CHARS,
        help="Default maximum chars returned by read_file tool.",
    )
    parser.add_argument(
        "--search-max-files",
        type=int,
        default=DEFAULT_SEARCH_MAX_FILES,
        help="Default max files scanned by search_pattern tool.",
    )
    parser.add_argument(
        "--search-max-matches",
        type=int,
        default=DEFAULT_SEARCH_MAX_MATCHES,
        help="Default max matches returned by search_pattern tool.",
    )
    parser.add_argument(
        "--search-rg-chunk-size",
        type=int,
        default=DEFAULT_SEARCH_RG_CHUNK_SIZE,
        help="Files per ripgrep batch when search_pattern uses the rg backend.",
    )
    parser.add_argument(
        "--overview-top-files",
        type=int,
        default=DEFAULT_OVERVIEW_TOP_FILES,
        help="How many top ranked files to include in source_overview text.",
    )
    parser.add_argument(
        "--fast-mode",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Apply a faster/smaller-context profile for local small-context models.",
    )
    parser.add_argument(
        "--lm-model",
        default=DEFAULT_LM_MODEL,
        help="Primary LM model for response generation.",
    )
    parser.add_argument(
        "--sub-lm-model",
        default=DEFAULT_SUB_LM_MODEL,
        help="Sub-LM model used by RLM planning/execution.",
    )
    parser.add_argument(
        "--lm-api-base",
        default=DEFAULT_LM_API_BASE,
        help="OpenAI-compatible API base URL.",
    )
    parser.add_argument(
        "--lm-max-tokens",
        type=int,
        default=DEFAULT_LM_MAX_TOKENS,
        help="Per-call maximum output tokens.",
    )
    parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="API key passed to model client.",
    )
    parser.add_argument(
        "--verbose",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_VERBOSE,
        help="Enable verbose RLM intermediate logs.",
    )
    parser.add_argument(
        "--skip-hidden-dirs",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_SKIP_HIDDEN_DIRS,
        help="Skip directories whose names start with '.'.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help="Number of retries after the initial attempt.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-attempt timeout in seconds; 0 disables timeout.",
    )
    parser.add_argument(
        "--backoff-seconds",
        type=float,
        default=DEFAULT_BACKOFF_SECONDS,
        help="Base seconds for exponential backoff between retries.",
    )
    parser.add_argument(
        "--output-report",
        type=Path,
        default=DEFAULT_OUTPUT_REPORT,
        help="Markdown output path for the audit report.",
    )
    parser.add_argument(
        "--output-metadata",
        type=Path,
        default=DEFAULT_OUTPUT_METADATA,
        help="JSON output path for run metadata.",
    )
    parser.add_argument(
        "--output-manifest",
        type=Path,
        default=DEFAULT_OUTPUT_MANIFEST,
        help="JSONL file path where indexed source manifest is written.",
    )
    return parser.parse_args()


def _check_prerequisites() -> None:
    deno = shutil.which("deno")
    if deno is None:
        # Common install path from the official install script.
        local_deno_bin = Path.home() / ".deno" / "bin"
        local_deno = local_deno_bin / "deno"
        if local_deno.exists():
            os.environ["PATH"] = f"{local_deno_bin}:{os.environ.get('PATH', '')}"
            deno = shutil.which("deno")

    if deno is None:
        raise RuntimeError(
            "dspy.RLM requires the 'deno' executable for its code interpreter.\n"
            "DENO_DIR only configures cache location; it does not install Deno.\n"
            "Install Deno and rerun: https://docs.deno.com/runtime/getting_started/installation/"
        )


def _normalize_lm_model_id(model: str, api_base: str) -> str:
    model = model.strip()
    if not model:
        raise ValueError("model cannot be empty")
    if "/" in model:
        return model
    api_base = api_base.strip()
    if api_base.startswith("http://") or api_base.startswith("https://"):
        # DSPy uses LiteLLM under the hood; OpenAI-compatible endpoints usually
        # require provider-qualified ids (openai/<model>).
        return f"openai/{model}"
    return model


def _build_lm(model: str, api_base: str, max_tokens: int, api_key: str) -> Any:
    return dspy.LM(
        model,
        api_base=api_base,
        max_tokens=max_tokens,
        api_key=api_key,
    )


class CodeScanner(dspy.Signature):
    """Security audit .NET code for vulnerabilities.

    Runtime workflow (important):
    - You are in a sandboxed interpreter. Host filesystem paths are not directly
      accessible.
    - Use provided tools (`list_manifest`, `read_file`, `search_pattern`) for
      all repository access.
    - Do NOT use `open()`, `os.listdir()`, `pathlib`, or direct file I/O for
      repository files.
    - Every action must be valid executable Python only (no markdown headings
      or prose in code blocks).
    - Read files lazily and only when needed.
    - Do NOT preload all file contents into memory and do NOT print huge dumps.
    - Start with targeted pattern scans per category, then inspect findings deeply.

    Check:
    - Injection: SQL (FromSqlRaw), Command, LDAP
    - Auth: JWT flaws, [Authorize] bypasses, missing auth checks
    - Deserialization: BinaryFormatter, NewtonSoft TypeNameHandling
    - XSS: @Html.Raw, unencoded Razor output
    - Secrets: Connection strings, API keys, passwords in code/config
    - Crypto: MD5/SHA1, hardcoded keys, cert bypass
    - Path traversal: Server.MapPath, file upload
    - SSRF: HttpClient without validation

    For each: Severity (CRITICAL/HIGH/MEDIUM/LOW), file:line, vulnerable code,
    attack scenario, secure fix, CWE reference.

    Output:
    ## Executive Summary (risk counts, top 3 threats)
    ## Critical Findings (CRITICAL/HIGH)
    ## Other Findings (MEDIUM/LOW)
    ## Remediation (immediate fixes, architecture improvements)"""

    source_overview: str = dspy.InputField(
        description="Compact repository index summary to guide targeted analysis."
    )
    documentation: str = dspy.OutputField(description=".NET security audit report")


def _score_manifest_entry(path: str, content_preview: str) -> tuple[int, int]:
    path_lower = path.lower()
    path_score = sum(1 for hint in SECURITY_PATH_HINTS if hint in path_lower)
    signal_score = len(SECURITY_SIGNAL_PATTERN.findall(content_preview))
    return signal_score, path_score


def _extension_priority(ext: str) -> int:
    return EXTENSION_PRIORITY.get(ext.lower(), 0)


@lru_cache(maxsize=256)
def _compile_pattern(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(pattern, flags)


def collect_source_manifest(
    root_dir: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    skip_hidden_dirs: bool,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    manifest: list[dict[str, Any]] = []
    stats = {
        "files": 0,
        "indexed_bytes": 0,
        "skipped_symlinks": 0,
        "skipped_hidden_dirs": 0,
        "skipped_configured_dirs": 0,
        "skipped_large_files": 0,
        "skipped_unreadable_dirs": 0,
        "skipped_unreadable_files": 0,
    }

    def walk(current_dir: Path, relative_prefix: str = "") -> None:
        if stats["files"] >= max_files:
            return

        try:
            entries = sorted(current_dir.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            stats["skipped_unreadable_dirs"] += 1
            return

        for path in entries:
            if stats["files"] >= max_files:
                return

            name = path.name
            if path.is_symlink():
                stats["skipped_symlinks"] += 1
                continue

            if path.is_dir():
                if name in SKIP_DIRS:
                    stats["skipped_configured_dirs"] += 1
                    continue
                if skip_hidden_dirs and name.startswith("."):
                    stats["skipped_hidden_dirs"] += 1
                    continue
                next_prefix = f"{relative_prefix}{name}/"
                walk(path, next_prefix)
                continue

            if name == "CONTENT" or not _is_audit_file(path):
                continue

            try:
                file_size = path.stat().st_size
            except OSError:
                stats["skipped_unreadable_files"] += 1
                continue

            if file_size > max_file_bytes:
                stats["skipped_large_files"] += 1
                continue

            rel_path = f"{relative_prefix}{name}"
            ext = Path(name).suffix.lower() or "<no_ext>"
            preview = ""
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    preview = handle.read(4096)
            except OSError:
                stats["skipped_unreadable_files"] += 1
                continue

            signal_score, path_score = _score_manifest_entry(rel_path, preview)
            manifest.append(
                {
                    "path": rel_path,
                    "bytes": file_size,
                    "ext": ext,
                    "signal_score": signal_score,
                    "path_score": path_score,
                }
            )
            stats["files"] += 1
            stats["indexed_bytes"] += file_size

    walk(root_dir)

    manifest.sort(
        key=lambda item: (
            -int(item["signal_score"]),
            -_extension_priority(str(item["ext"])),
            -int(item["path_score"]),
            -int(item["bytes"]),
            item["path"],
        )
    )
    return manifest, stats


def build_source_overview(
    manifest: list[dict[str, Any]],
    *,
    overview_top_files: int,
) -> tuple[str, dict[str, Any]]:
    if not manifest:
        summary: dict[str, Any] = {
            "top_extensions": [],
            "top_directories": [],
            "top_signal_files": [],
        }
        return "No files indexed.", summary

    ext_counts: dict[str, int] = {}
    top_dirs: dict[str, int] = {}
    for entry in manifest:
        ext = str(entry["ext"])
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

        path = str(entry["path"])
        top_dir = path.split("/", 1)[0] if "/" in path else "<root>"
        top_dirs[top_dir] = top_dirs.get(top_dir, 0) + 1

    sorted_ext_counts = sorted(
        ext_counts.items(), key=lambda item: (-item[1], item[0])
    )
    sorted_top_dirs = sorted(top_dirs.items(), key=lambda item: (-item[1], item[0]))

    top_extensions = [
        {"extension": ext, "count": count}
        for ext, count in sorted_ext_counts[:20]
    ]
    top_directories = [
        {"directory": name, "count": count}
        for name, count in sorted_top_dirs[:20]
    ]
    top_signal_files = manifest[:120]

    ext_summary = ", ".join(
        f"{item['extension']}:{item['count']}" for item in top_extensions
    )
    dir_summary = ", ".join(
        f"{item['directory']}:{item['count']}" for item in top_directories
    )
    signal_summary = "\n".join(
        "- "
        + f"{entry['path']} (signal={entry['signal_score']}, "
        + f"path={entry['path_score']}, bytes={entry['bytes']})"
        for entry in top_signal_files[:overview_top_files]
    )

    overview = (
        f"Indexed files: {len(manifest)}\n"
        f"Top extensions: {ext_summary}\n"
        f"Top directories: {dir_summary}\n"
        "Top candidate files (ranked):\n"
        f"{signal_summary}"
    )
    summary = {
        "top_extensions": top_extensions,
        "top_directories": top_directories,
        "top_signal_files": top_signal_files,
    }
    return overview, summary


def write_manifest_jsonl(
    manifest: list[dict[str, Any]],
    *,
    manifest_path: Path,
) -> Path:
    resolved_manifest = manifest_path.expanduser().resolve()
    resolved_manifest.parent.mkdir(parents=True, exist_ok=True)

    with resolved_manifest.open("w", encoding="utf-8") as handle:
        for entry in manifest:
            handle.write(json.dumps(entry, separators=(",", ":")) + "\n")

    return resolved_manifest


def _normalize_relative_path(relative_path: str) -> str:
    normalized = relative_path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _resolve_repo_path(source_root: Path, relative_path: str) -> Path:
    normalized = _normalize_relative_path(relative_path)
    if not normalized:
        raise ValueError("relative_path cannot be empty")
    if normalized.startswith("/"):
        raise ValueError("relative_path must be repository-relative, not absolute")

    candidate = (source_root / normalized).resolve()
    try:
        candidate.relative_to(source_root)
    except ValueError as exc:
        raise ValueError("relative_path escapes source_root") from exc
    return candidate


def build_rlm_tools(
    source_root: Path,
    manifest: list[dict[str, Any]],
    *,
    default_tool_max_lines: int,
    default_tool_max_chars: int,
    default_search_max_files: int,
    default_search_max_matches: int,
    default_search_rg_chunk_size: int = DEFAULT_SEARCH_RG_CHUNK_SIZE,
) -> list[Any]:
    manifest_by_path: dict[str, dict[str, Any]] = {}
    for entry in manifest:
        normalized = _normalize_relative_path(str(entry["path"]))
        manifest_by_path[normalized] = entry

    ordered_paths = list(manifest_by_path.keys())
    lower_paths = {path: path.lower() for path in ordered_paths}
    paths_by_ext: dict[str, list[str]] = {}
    for path in ordered_paths:
        ext_key = str(manifest_by_path[path].get("ext", "")).lower()
        paths_by_ext.setdefault(ext_key, []).append(path)
    rg_bin = shutil.which("rg")

    @lru_cache(maxsize=64)
    def _read_text_cached(normalized_path: str) -> str:
        target = _resolve_repo_path(source_root, normalized_path)
        return target.read_text(encoding="utf-8", errors="ignore")

    def _iter_filtered_paths(ext: str, path_contains: str) -> Iterator[str]:
        base_paths = paths_by_ext.get(ext, []) if ext else ordered_paths
        if not path_contains:
            for path in base_paths:
                yield path
            return

        for path in base_paths:
            if path_contains in lower_paths[path]:
                yield path

    def tool_help() -> dict[str, Any]:
        """Return tool usage rules and examples for repository access."""
        return {
            "rules": [
                "Use tools for all repository file access.",
                "Do not use open/os/pathlib for repo files in sandbox code.",
                "Prefer search_pattern() then read_file() around matched lines.",
            ],
            "examples": [
                "list_manifest(limit=30, min_signal_score=1)",
                "search_pattern(r'FromSqlRaw|ExecuteSqlRaw', ext='.cs')",
                "read_file('src/MyController.cs', start_line=120, max_lines=80)",
            ],
        }

    def list_manifest(
        limit: int = 200,
        limit_files: int = 0,
        min_signal_score: int = 0,
        ext: str = "",
        path_contains: str = "",
    ) -> list[dict[str, Any]]:
        """List indexed files from the ranked manifest with optional filters."""
        if limit_files > 0:
            limit = limit_files
        limit = max(1, min(limit, 2000))
        ext = ext.lower().strip()
        path_contains = path_contains.lower().strip()

        selected: list[dict[str, Any]] = []
        for path in _iter_filtered_paths(ext, path_contains):
            entry = manifest_by_path[path]
            if int(entry.get("signal_score", 0)) < min_signal_score:
                continue
            selected.append(entry)
            if len(selected) >= limit:
                break
        return selected

    def read_file(
        relative_path: str,
        start_line: int = 1,
        max_lines: int = 0,
        max_chars: int = 0,
    ) -> dict[str, Any]:
        """Read a repository file snippet with line numbers and size limits."""
        normalized = _normalize_relative_path(relative_path)
        if normalized not in manifest_by_path:
            raise ValueError(f"Path not indexed in manifest: {normalized}")

        max_lines = default_tool_max_lines if max_lines <= 0 else max_lines
        max_chars = default_tool_max_chars if max_chars <= 0 else max_chars
        max_lines = max(1, min(max_lines, 2000))
        max_chars = max(256, min(max_chars, 300000))
        start_line = max(1, start_line)

        text = _read_text_cached(normalized)
        lines = text.splitlines()
        total_lines = len(lines)

        start_idx = min(start_line - 1, total_lines)
        end_idx = min(total_lines, start_idx + max_lines)

        numbered_lines: list[str] = []
        current_chars = 0
        truncated = False
        for idx in range(start_idx, end_idx):
            rendered = f"{idx + 1}: {lines[idx]}"
            next_size = current_chars + len(rendered) + 1
            if next_size > max_chars:
                truncated = True
                break
            numbered_lines.append(rendered)
            current_chars = next_size

        if end_idx < total_lines:
            truncated = True

        return {
            "path": normalized,
            "start_line": start_idx + 1 if total_lines else 0,
            "end_line": (start_idx + len(numbered_lines)) if total_lines else 0,
            "total_lines": total_lines,
            "truncated": truncated,
            "content": "\n".join(numbered_lines),
        }

    def search_pattern(
        pattern: str,
        ignore_case: bool = True,
        ext: str = "",
        path_contains: str = "",
        limit_files: int = 0,
        limit_matches: int = 0,
    ) -> list[dict[str, Any]]:
        """Regex search across indexed files; returns path/line/preview matches."""
        if not pattern.strip():
            raise ValueError("pattern cannot be empty")

        ext = ext.lower().strip()
        path_contains = path_contains.lower().strip()
        limit_files = default_search_max_files if limit_files <= 0 else limit_files
        limit_matches = (
            default_search_max_matches if limit_matches <= 0 else limit_matches
        )
        limit_files = max(1, min(limit_files, 10000))
        limit_matches = max(1, min(limit_matches, 5000))
        try:
            regex = _compile_pattern(pattern, ignore_case)
        except re.error as exc:
            raise ValueError(f"invalid regex pattern: {exc}") from exc

        candidate_paths = []
        for rel_path in _iter_filtered_paths(ext, path_contains):
            candidate_paths.append(rel_path)
            if len(candidate_paths) >= limit_files:
                break

        if not candidate_paths:
            return []

        def _search_with_rg() -> list[dict[str, Any]] | None:
            if rg_bin is None:
                return None

            matches: list[dict[str, Any]] = []
            remaining = limit_matches
            chunk_size = max(1, min(default_search_rg_chunk_size, 256))

            for start_idx in range(0, len(candidate_paths), chunk_size):
                if remaining <= 0:
                    break

                chunk = candidate_paths[start_idx : start_idx + chunk_size]
                cmd = [
                    rg_bin,
                    "--no-config",
                    "--json",
                    "--line-number",
                    "--color",
                    "never",
                    "--max-count",
                    str(remaining),
                ]
                if ignore_case:
                    cmd.append("--ignore-case")
                cmd.extend(["-e", pattern])
                cmd.extend(chunk)

                try:
                    result = subprocess.run(
                        cmd,
                        cwd=source_root,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                except OSError:
                    return None

                if result.returncode not in (0, 1):
                    # Fallback to Python regex backend on rg parse/engine errors.
                    return None

                if not result.stdout:
                    continue

                for line in result.stdout.splitlines():
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        return None
                    if event.get("type") != "match":
                        continue

                    data = event.get("data", {})
                    path_obj = data.get("path", {})
                    path_text = path_obj.get("text") if isinstance(path_obj, dict) else ""
                    if not isinstance(path_text, str):
                        continue
                    normalized = _normalize_relative_path(path_text)
                    if normalized not in manifest_by_path:
                        continue

                    line_no_obj = data.get("line_number", 0)
                    try:
                        line_no = int(line_no_obj)
                    except (TypeError, ValueError):
                        line_no = 0

                    lines_obj = data.get("lines", {})
                    preview = lines_obj.get("text", "") if isinstance(lines_obj, dict) else ""
                    if not isinstance(preview, str):
                        preview = str(preview)
                    preview = preview.rstrip("\n")
                    if len(preview) > 300:
                        preview = preview[:300] + "..."

                    matches.append(
                        {
                            "path": normalized,
                            "line": line_no,
                            "preview": preview,
                        }
                    )
                    remaining -= 1
                    if remaining <= 0:
                        break

            return matches

        rg_matches = _search_with_rg()
        if rg_matches is not None:
            return rg_matches

        matches: list[dict[str, Any]] = []
        for rel_path in candidate_paths:
            target = _resolve_repo_path(source_root, rel_path)
            try:
                with target.open("r", encoding="utf-8", errors="ignore") as handle:
                    for line_no, line in enumerate(handle, start=1):
                        if not regex.search(line):
                            continue
                        preview = line.rstrip("\n")
                        if len(preview) > 300:
                            preview = preview[:300] + "..."
                        matches.append(
                            {
                                "path": rel_path,
                                "line": line_no,
                                "preview": preview,
                            }
                        )
                        if len(matches) >= limit_matches:
                            return matches
            except OSError:
                continue

        return matches

    return [tool_help, list_manifest, read_file, search_pattern]


class AuditTimeoutError(TimeoutError):
    """Raised when an audit attempt exceeds the configured timeout."""


@contextmanager
def timeout_guard(seconds: int) -> Iterator[None]:
    if (
        seconds <= 0
        or not hasattr(signal, "SIGALRM")
        or not hasattr(signal, "ITIMER_REAL")
    ):
        yield
        return

    def _handle_timeout(_signum: int, _frame: Any) -> None:
        raise AuditTimeoutError(f"Audit attempt exceeded {seconds} seconds.")

    try:
        previous_handler = signal.signal(signal.SIGALRM, _handle_timeout)
    except ValueError:
        # signal alarms only work in the main thread.
        yield
        return

    signal.setitimer(signal.ITIMER_REAL, float(seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)


def run_audit_with_retry(
    code_scanner: Any,
    *,
    source_overview: str,
    retries: int,
    timeout_seconds: int,
    backoff_seconds: float,
) -> tuple[Any, int, float]:
    attempts = retries + 1
    for attempt in range(1, attempts + 1):
        attempt_started = time.monotonic()
        print(
            f"Starting audit attempt {attempt}/{attempts} "
            f"(timeout={timeout_seconds}s)..."
        )
        stop_event = threading.Event()

        def _heartbeat() -> None:
            while not stop_event.wait(20):
                elapsed = time.monotonic() - attempt_started
                print(
                    f"Audit attempt {attempt}/{attempts} still running "
                    f"({elapsed:.0f}s elapsed)..."
                )

        heartbeat_thread = threading.Thread(target=_heartbeat, daemon=True)
        heartbeat_thread.start()
        try:
            with timeout_guard(timeout_seconds):
                result = code_scanner(
                    source_overview=source_overview,
                )
            stop_event.set()
            heartbeat_thread.join(timeout=1)
            attempt_duration = time.monotonic() - attempt_started
            print(
                f"Audit attempt {attempt}/{attempts} completed "
                f"in {attempt_duration:.1f}s."
            )
            return result, attempt, attempt_duration
        except Exception as exc:
            stop_event.set()
            heartbeat_thread.join(timeout=1)
            if attempt >= attempts:
                raise RuntimeError(
                    f"Audit failed after {attempts} attempts."
                ) from exc

            sleep_seconds = backoff_seconds * (2 ** (attempt - 1))
            print(
                f"Attempt {attempt}/{attempts} failed: {exc}. "
                f"Retrying in {sleep_seconds:.1f}s..."
            )
            time.sleep(sleep_seconds)

    raise RuntimeError("Audit failed unexpectedly.")


def write_artifacts(
    report: str,
    metadata: dict[str, Any],
    *,
    report_path: Path,
    metadata_path: Path,
) -> tuple[Path, Path]:
    resolved_report = report_path.expanduser().resolve()
    resolved_metadata = metadata_path.expanduser().resolve()
    resolved_report.parent.mkdir(parents=True, exist_ok=True)
    resolved_metadata.parent.mkdir(parents=True, exist_ok=True)

    resolved_report.write_text(report, encoding="utf-8")
    resolved_metadata.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return resolved_report, resolved_metadata


def main() -> int:
    args = parse_args()
    source_root = args.source_root.expanduser().resolve()
    if not source_root.is_dir():
        raise RuntimeError(
            f"Source root does not exist or is not a directory: {source_root}"
        )

    if args.max_iterations <= 0:
        raise ValueError("--max-iterations must be > 0")
    if args.max_files <= 0:
        raise ValueError("--max-files must be > 0")
    if args.max_file_bytes <= 0:
        raise ValueError("--max-file-bytes must be > 0")
    if args.rlm_max_llm_calls <= 0:
        raise ValueError("--rlm-max-llm-calls must be > 0")
    if args.rlm_max_output_chars <= 0:
        raise ValueError("--rlm-max-output-chars must be > 0")
    if args.tool_max_lines <= 0:
        raise ValueError("--tool-max-lines must be > 0")
    if args.tool_max_chars <= 0:
        raise ValueError("--tool-max-chars must be > 0")
    if args.search_max_files <= 0:
        raise ValueError("--search-max-files must be > 0")
    if args.search_max_matches <= 0:
        raise ValueError("--search-max-matches must be > 0")
    if args.search_rg_chunk_size <= 0:
        raise ValueError("--search-rg-chunk-size must be > 0")
    if args.overview_top_files <= 0:
        raise ValueError("--overview-top-files must be > 0")
    if args.lm_max_tokens <= 0:
        raise ValueError("--lm-max-tokens must be > 0")
    if args.retries < 0:
        raise ValueError("--retries must be >= 0")
    if args.timeout_seconds < 0:
        raise ValueError("--timeout-seconds must be >= 0")
    if args.backoff_seconds < 0:
        raise ValueError("--backoff-seconds must be >= 0")

    if os.getenv("AUDIT_VERBOSE") == "1" and not args.verbose:
        print(
            "Note: verbose RLM logs are disabled by CLI/options "
            "(AUDIT_VERBOSE=1 is currently overridden)."
        )

    if args.fast_mode:
        if args.max_iterations > 8:
            args.max_iterations = 8
        if args.rlm_max_llm_calls > 32:
            args.rlm_max_llm_calls = 32
        if args.rlm_max_output_chars > 12000:
            args.rlm_max_output_chars = 12000
        if args.lm_max_tokens > 2048:
            args.lm_max_tokens = 2048
        if args.max_files > 3000:
            args.max_files = 3000
        if args.search_max_files > 800:
            args.search_max_files = 800
        if args.search_max_matches > 150:
            args.search_max_matches = 150
        if args.search_rg_chunk_size > 32:
            args.search_rg_chunk_size = 32
        if args.overview_top_files > 20:
            args.overview_top_files = 20
        print(
            "Fast mode enabled: "
            f"iterations={args.max_iterations}, "
            f"lm_max_tokens={args.lm_max_tokens}, "
            f"rlm_max_llm_calls={args.rlm_max_llm_calls}, "
            f"overview_top_files={args.overview_top_files}"
        )

    _check_prerequisites()

    manifest, stats = collect_source_manifest(
        source_root,
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        skip_hidden_dirs=args.skip_hidden_dirs,
    )
    if not manifest:
        raise RuntimeError(
            f"No files indexed from {source_root}. Check filters/limits."
        )

    print(
        f"Indexed {stats['files']} files "
        f"({stats['indexed_bytes']} bytes) from {source_root}."
    )

    manifest_file = write_manifest_jsonl(manifest, manifest_path=args.output_manifest)
    print(f"Wrote manifest to {manifest_file}")

    source_overview, overview_summary = build_source_overview(
        manifest,
        overview_top_files=args.overview_top_files,
    )
    source_overview += (
        "\n\nExecution guidance:\n"
        "- Use tools only: tool_help(), list_manifest(), search_pattern(), read_file().\n"
        "- Sandbox cannot directly read host repo paths.\n"
        "- Never use open(), os.listdir(), pathlib, or direct repo file I/O.\n"
        "- Start with targeted regex searches for vulnerability categories, then inspect snippets.\n"
        "- Keep intermediate output concise.\n"
        "\nRecommended first-step code:\n"
        "help_info = tool_help()\n"
        "print(help_info)\n"
        "seed = list_manifest(limit=30, min_signal_score=1)\n"
        "print(seed[:5])"
    )
    tools = build_rlm_tools(
        source_root,
        manifest,
        default_tool_max_lines=args.tool_max_lines,
        default_tool_max_chars=args.tool_max_chars,
        default_search_max_files=args.search_max_files,
        default_search_max_matches=args.search_max_matches,
        default_search_rg_chunk_size=args.search_rg_chunk_size,
    )
    rg_available = shutil.which("rg") is not None
    if rg_available:
        print("search_pattern backend: rg (auto-fallback to python).")
    else:
        print("search_pattern backend: python (rg not found).")

    effective_lm_model = _normalize_lm_model_id(args.lm_model, args.lm_api_base)
    effective_sub_lm_model = _normalize_lm_model_id(
        args.sub_lm_model, args.lm_api_base
    )
    if effective_lm_model != args.lm_model:
        print(
            "Normalized --lm-model for LiteLLM/OpenAI compatibility: "
            f"{args.lm_model} -> {effective_lm_model}"
        )
    if effective_sub_lm_model != args.sub_lm_model:
        print(
            "Normalized --sub-lm-model for LiteLLM/OpenAI compatibility: "
            f"{args.sub_lm_model} -> {effective_sub_lm_model}"
        )

    lm = _build_lm(
        model=effective_lm_model,
        api_base=args.lm_api_base,
        max_tokens=args.lm_max_tokens,
        api_key=args.api_key,
    )
    sub_lm = _build_lm(
        model=effective_sub_lm_model,
        api_base=args.lm_api_base,
        max_tokens=args.lm_max_tokens,
        api_key=args.api_key,
    )
    dspy.configure(lm=lm)

    code_scanner = dspy.RLM(
        CodeScanner,
        max_iterations=args.max_iterations,
        max_llm_calls=args.rlm_max_llm_calls,
        max_output_chars=args.rlm_max_output_chars,
        sub_lm=sub_lm,
        tools=tools,
        verbose=args.verbose,
    )

    started_utc = datetime.now(timezone.utc)
    run_started = time.monotonic()
    result, attempts_used, final_attempt_seconds = run_audit_with_retry(
        code_scanner,
        source_overview=source_overview,
        retries=args.retries,
        timeout_seconds=args.timeout_seconds,
        backoff_seconds=args.backoff_seconds,
    )
    run_duration = time.monotonic() - run_started

    report = result.documentation
    print(report)

    finished_utc = datetime.now(timezone.utc)
    metadata = {
        "run_started_utc": started_utc.isoformat(),
        "run_finished_utc": finished_utc.isoformat(),
        "duration_seconds": round(run_duration, 3),
        "attempts_used": attempts_used,
        "max_attempts": args.retries + 1,
        "final_attempt_seconds": round(final_attempt_seconds, 3),
        "source_root": str(source_root),
        "manifest_path": str(manifest_file),
        "files_indexed": stats["files"],
        "bytes_indexed": stats["indexed_bytes"],
        "limits": {
            "max_iterations": args.max_iterations,
            "max_files": args.max_files,
            "max_file_bytes": args.max_file_bytes,
            "rlm_max_llm_calls": args.rlm_max_llm_calls,
            "rlm_max_output_chars": args.rlm_max_output_chars,
            "overview_top_files": args.overview_top_files,
            "tool_max_lines": args.tool_max_lines,
            "tool_max_chars": args.tool_max_chars,
            "search_max_files": args.search_max_files,
            "search_max_matches": args.search_max_matches,
            "search_rg_chunk_size": args.search_rg_chunk_size,
            "timeout_seconds": args.timeout_seconds,
            "backoff_seconds": args.backoff_seconds,
        },
        "models": {
            "primary": args.lm_model,
            "sub_lm": args.sub_lm_model,
            "primary_resolved": effective_lm_model,
            "sub_lm_resolved": effective_sub_lm_model,
            "api_base": args.lm_api_base,
            "max_tokens": args.lm_max_tokens,
        },
        "flags": {
            "verbose": args.verbose,
            "skip_hidden_dirs": args.skip_hidden_dirs,
            "fast_mode": args.fast_mode,
            "rg_available": rg_available,
        },
        "loader_stats": {
            "skipped_symlinks": stats["skipped_symlinks"],
            "skipped_hidden_dirs": stats["skipped_hidden_dirs"],
            "skipped_configured_dirs": stats["skipped_configured_dirs"],
            "skipped_large_files": stats["skipped_large_files"],
            "skipped_unreadable_dirs": stats["skipped_unreadable_dirs"],
            "skipped_unreadable_files": stats["skipped_unreadable_files"],
        },
        "overview": overview_summary,
        "report_chars": len(report),
    }

    saved_report, saved_metadata = write_artifacts(
        report,
        metadata,
        report_path=args.output_report,
        metadata_path=args.output_metadata,
    )
    print(f"Saved report to {saved_report}")
    print(f"Saved metadata to {saved_metadata}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
