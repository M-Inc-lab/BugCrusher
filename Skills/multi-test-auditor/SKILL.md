---
name: multi-test-auditor
description: Run multi-phase critical audit on any codebase. Covers unit tests, integration tests, security tests, performance benchmarks, and logic correctness. Use when user asks to "audit", "test thoroughly", "run all tests", or "critically review" a project. Generates AUDIT_REPORT.md.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
allowed-tools: Bash, Read, Grep
---

# Multi-Test Auditor Skill

Run a thorough, reproducible audit of any software project in 7 phases.

## When to Use

- User says "audit", "critically review", "test thoroughly", "run all tests"
- After cloning a new repository
- Before major deployments or releases
- When bringing a new project into the workspace

## Usage

```bash
python3 Skills/multi-test-auditor/scripts/run_audit.py /path/to/project [--phases=1-7]
```

## Phases

### Phase 1: Reconnaissance
File counts, LOC by language, README/doc presence, directory structure.

### Phase 2: Dependency Check
Validate all packages in requirements.txt are installed. Catch version drift.

### Phase 3: Test Execution
Discover test files (`test_*.py`, `*_test.py`, `tests/`, `spec/`). Run pytest and assert pass/fail/skip counts. **CRITICAL** if project has no tests at all.

### Phase 4: Database Integrity (SQLite projects only)
PRAGMA integrity_check, orphaned records, NULL constraints, referential integrity.

### Phase 5: Security Review
- Command injection: `shell=True` with f-string interpolation (CRITICAL)
- Dangerous eval/exec: only if evaluating user/input data (not test vectors)
- Hardcoded credentials: real secrets, not placeholder strings
- SQL injection: string concatenation in execute()
- Path traversal: unsanitized file operations

### Phase 6: Logic Audit
- Bare `except:` in critical paths (not blanket — context-sensitive)
- `is None` not `== None`
- `enumerate()` not `range(len())`
- f-strings not % formatting
- Mutable default arguments

### Phase 7: Report Generation
Write `AUDIT_REPORT.md` with findings categorized by severity and per-phase summary.

## Output

Always produce `AUDIT_REPORT.md` with:
1. Per-phase summary (file count, LOC, test results, security issues, logic bugs)
2. Security findings by severity
3. Logic bugs by type and location
4. Project-specific recommendations (not generic templates)

## Test Coverage Matrix

| Category | What's Checked |
|----------|---------------|
| Unit Tests | Pass/fail/skip/error counts |
| Security | Shell injection, eval/exec, hardcoded secrets |
| Logic | Exception handling, formatting, mutable args |
| DB Integrity | Orphaned records, NULL CVSS, constraint violations |
| Dependencies | Missing packages, version drift |
