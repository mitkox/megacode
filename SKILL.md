---
name: security-audit-rlm
description: "Run and troubleshoot privacy-preserving, local DSPy RLM security audits for large legacy .NET codebases. Use when asked to scan repositories for vulnerabilities, tune RLM/tool limits, fix truncation/stall issues, or produce actionable markdown/json audit outputs without loading entire codebases into model context."
---

# Security Audit RLM

Use this skill to operate `audit.py` as a tool-driven RLM workflow for large repositories.

Repository: `https://github.com/mitkox/megacode`

## Execute

1. Verify prerequisites:
   ```bash
   deno --version
   curl -s http://localhost:8000/v1/models | head -5
   ```
2. Run a baseline audit:
   ```bash
   AUDIT_VERBOSE=1 python audit.py --source-root <repo-path>
   ```
3. Validate the run succeeded:
   ```bash
   # Check exit code (0 = success)
   echo $?
   # Verify all three output files exist and are non-empty
   test -s security_audit_report.md && echo "Report OK"
   test -s security_audit_metadata.json && echo "Metadata OK"
   test -s security_audit_manifest.jsonl && echo "Manifest OK"
   # Confirm metadata contains expected keys
   python -c "import json; d=json.load(open('security_audit_metadata.json')); print(f\"Findings: {d.get('finding_count', 'MISSING')}\")"
   ```

## Recommended Configuration for Large Legacy .NET Repos

Copy-paste starting point for repos with 2000+ files:

```bash
python audit.py \
  --source-root ~/dev/MyLegacyApp \
  --max-iterations 10 \
  --max-files 6000 \
  --rlm-max-llm-calls 80 \
  --rlm-max-output-chars 20000 \
  --tool-max-lines 300 \
  --tool-max-chars 30000 \
  --search-max-files 1200 \
  --search-max-matches 300 \
  --timeout-seconds 900 \
  --verbose
```

Adjust from this baseline:
- **Faster/smaller runs**: lower `--max-iterations` to 6, `--timeout-seconds` to 600, add `--fast-mode`
- **Deeper analysis**: raise `--max-iterations` to 12, `--rlm-max-llm-calls` to 100
- **Smaller context models**: lower `--rlm-max-output-chars` to 15000, `--tool-max-chars` to 20000

## Operating Rules

- Keep analysis local when privacy constraints require it.
- Use RLM tool access, not full-context repository injection.
- Keep intermediate output concise and deterministic.
- Prioritize high-severity findings with file/line evidence and concrete fixes.

## Troubleshooting

- **Run appears stalled** (no output after 60s):
  ```bash
  # Confirm verbose is on to see RLM iteration logs
  AUDIT_VERBOSE=1 python audit.py --source-root <repo-path> --max-iterations 6
  ```
- **Model output truncates mid-report**:
  ```bash
  # Check how many manifest entries were indexed
  wc -l security_audit_manifest.jsonl
  # Re-run with tighter limits
  python audit.py --source-root <repo-path> --rlm-max-output-chars 15000 --lm-max-tokens 8192 --max-iterations 8
  ```
- **Path/file access errors in RLM steps**:
  ```bash
  # Verify the tool functions are registered
  python -c "import audit; print([t for t in dir(audit) if t.startswith('tool_')])"
  ```

## Deliverable Format

Ensure report sections remain:

1. Executive Summary
2. Critical Findings (CRITICAL/HIGH)
3. Other Findings (MEDIUM/LOW)
4. Remediation
