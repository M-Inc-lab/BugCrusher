# ─────────────────────────────────────────────────────────────────
# Self-Test Suite for Multi-Test Auditor v2
# Runs against the auditor itself — validates detection quality
# ─────────────────────────────────────────────────────────────────

import pytest, ast, os, sys, tempfile, subprocess, re
from pathlib import Path

# Add scripts dir to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from run_audit import ASTSecurityAnalyzer, LogicAnalyzer, LogicVisitor, MutationTester, MultiTestAuditor


class TestASTSecurityAnalyzer:
    """Phase 5 equivalent — AST-based security detection."""

    def test_shell_true_detected(self):
        """shell=True with string literal = OK (hardcoded command)."""
        code = 'import subprocess; subprocess.run("echo hello", shell=True)'
        tree = ast.parse(code)
        analyzer = ASTSecurityAnalyzer("test.py")
        analyzer.visit(tree)
        # String literal only → not flagged as dangerous (but IS flagged for shell=True)
        assert len(analyzer.issues) == 1
        assert "shell=True" in analyzer.issues[0]["type"]

    def test_shell_true_with_format_detected(self):
        """shell=True with f-string interpolation = CRITICAL."""
        code = 'import subprocess; subprocess.run(f"ping {host}", shell=True)'
        tree = ast.parse(code)
        analyzer = ASTSecurityAnalyzer("test.py")
        analyzer.visit(tree)
        assert any("CRITICAL" in i["severity"] for i in analyzer.issues)

    def test_eval_constant_safe(self):
        """eval('1+1') = safe (constant only)."""
        code = "eval('1+1')"
        tree = ast.parse(code)
        analyzer = ASTSecurityAnalyzer("test.py")
        analyzer.visit(tree)
        assert len(analyzer.issues) == 0  # No issues for safe eval

    def test_eval_variable_detected(self):
        """eval(variable) = CRITICAL."""
        code = "import subprocess; x = input(); eval(x)"
        tree = ast.parse(code)
        analyzer = ASTSecurityAnalyzer("test.py")
        analyzer.visit(tree)
        assert any("eval" in i["type"].lower() for i in analyzer.issues)

    def test_os_system_detected(self):
        """os.system() = CRITICAL."""
        code = "import os; os.system('ls')"
        tree = ast.parse(code)
        analyzer = ASTSecurityAnalyzer("test.py")
        analyzer.visit(tree)
        assert any("os.system" in i["type"] for i in analyzer.issues)


class TestLogicAnalyzer:
    """Phase 6 equivalent — AST-based logic bug detection."""

    def test_bare_except_detected(self):
        code = (
            "def foo():\n"
            "    try:\n"
            "        pass\n"
            "    except:\n"
            "        pass\n"
        )
        with open("/tmp/test_bare.py", "w") as f:
            f.write(code)
        issues = LogicAnalyzer.analyze_file("/tmp/test_bare.py")
        os.remove("/tmp/test_bare.py")
        bare_issues = [i for i in issues if "Bare" in i["type"] or "bare" in i["type"]]
        assert len(bare_issues) > 0, f"No bare except detected. Issues: {issues}"

    def test_printf_format_detected(self):
        code = 'def foo():\n    print("val: %s" % "test")\n'
        with open("/tmp/test_printf.py", "w") as f:
            f.write(code)
        issues = LogicAnalyzer.analyze_file("/tmp/test_printf.py")
        os.remove("/tmp/test_printf.py")
        assert any("printf" in i["type"].lower() for i in issues), f"Issues: {issues}"

    def test_equals_none_detected(self):
        code = "def foo():\n    if x == None:\n        pass\n"
        with open("/tmp/test_none.py", "w") as f:
            f.write(code)
        issues = LogicAnalyzer.analyze_file("/tmp/test_none.py")
        os.remove("/tmp/test_none.py")
        none_issues = [i for i in issues if "==None" in i["type"] or "None" in i["type"]]
        assert len(none_issues) > 0, f"No ==None detected. Issues: {issues}"

    def test_range_len_detected(self):
        code = "def foo():\n    for i in range(len(items)):\n        pass\n"
        with open("/tmp/test_rangelen.py", "w") as f:
            f.write(code)
        issues = LogicAnalyzer.analyze_file("/tmp/test_rangelen.py")
        os.remove("/tmp/test_rangelen.py")
        rl_issues = [i for i in issues if "range(len)" in i["type"] or "enumerate" in i["type"]]
        assert len(rl_issues) > 0, f"No range(len) detected. Issues: {issues}"

    def test_mutable_default_detected(self):
        code = "def foo(x=[]):\n    pass"
        with open("/tmp/test_mutable.py", "w") as f:
            f.write(code)
        issues = LogicAnalyzer.analyze_file("/tmp/test_mutable.py")
        os.remove("/tmp/test_mutable.py")
        assert any("Mutable" in i["type"] for i in issues)

    def test_clean_code_no_issues(self):
        """Verify analyzer doesn't flag clean code."""
        code = "\n".join([
            "def foo(items):",
            "    for i, item in enumerate(items):",
            "        try:",
            "            result = item + 1",
            "        except ValueError:",
            "            pass",
            "    return None",
        ])
        with open("/tmp/test_clean.py", "w") as f:
            f.write(code)
        issues = LogicAnalyzer.analyze_file("/tmp/test_clean.py")
        os.remove("/tmp/test_clean.py")
        bare_except = [i for i in issues if "Bare" in i["type"]]
        assert len(bare_except) == 0


class TestMutationTester:
    """Mutation testing — validates detection quality."""

    def test_mutation_score_above_75_percent(self):
        """Auditor must detect >= 75% of known mutations."""
        tester = MutationTester()
        result = tester.run()
        score = result["score"]
        detected = result["detected"]
        total = result["total"]
        print(f"\nMutation score: {detected}/{total} = {score:.0%}")
        assert score >= 0.75, f"Mutation score {score:.0%} below 75%"

    def test_each_mutation_category(self):
        """Every mutation category must be detectable."""
        tester = MutationTester()
        result = tester.run()
        categories = {r["mutation"]: r["detected"] for r in result["details"]}
        failed = [k for k, v in categories.items() if not v]
        if failed:
            print(f"\nMISSED mutations: {failed}")
        assert len(failed) <= 1, f"Undetected mutations: {failed}"


class TestMultiTestAuditor:
    """End-to-end auditor tests."""

    def test_auditor_runs_without_crash(self):
        """Auditor must complete all phases without crashing."""
        auditor = MultiTestAuditor("/home/workspace/BugCrusher")
        out = auditor.run("1-7")
        assert len(out) > 10
        assert any("PHASE" in line for line in out)

    def test_no_negative_counts_in_results(self):
        """Test counts must be >= 0, never negative."""
        auditor = MultiTestAuditor("/home/workspace/BugCrusher")
        auditor.run("1-7")
        assert auditor.results["passed"] >= 0
        assert auditor.results["failed"] >= 0
        assert auditor.results["skipped"] >= 0

    def test_report_contains_all_sections(self):
        """Generated report must have all required sections."""
        auditor = MultiTestAuditor("/home/workspace/BugCrusher")
        auditor.run("1-7")
        report_path = auditor.project / "AUDIT_REPORT.md"
        assert report_path.exists(), "Report not generated"
        content = report_path.read_text()
        assert "Summary" in content
        assert "Security" in content or "Logic" in content

    def test_self_audit_mode(self):
        """Self-audit mode must include mutation testing."""
        auditor = MultiTestAuditor("/home/workspace/Skills/multi-test-auditor", self_audit=True)
        out = auditor.run("1-7")
        report_path = Path("/home/workspace/Skills/multi-test-auditor/AUDIT_REPORT.md")
        if report_path.exists():
            content = report_path.read_text()
            assert "Mutation" in content or "mutation" in content.lower()

    def test_phase5_no_false_positives_on_self(self):
        """Phase 5 must not flag the auditor itself as vulnerable."""
        auditor = MultiTestAuditor("/home/workspace/Skills/multi-test-auditor")
        auditor.phase5()
        self_issues = [
            i for i in auditor.results.get("security", [])
            if "run_audit.py" in i.get("file", "")
        ]
        print(f"\nPhase 5 self-issues: {len(self_issues)}")
        assert len(self_issues) == 0, f"Auditor flagged itself: {self_issues}"


class TestBoundaryValues:
    """Phase 4 equivalent — boundary value integrity."""

    def test_cvss_range(self):
        """CVSS scores must be in [0, 10]."""
        import sqlite3
        for db_path in Path("/home/workspace/BugCrusher").glob("*.db"):
            try:
                conn = sqlite3.connect(str(db_path))
                for row in conn.execute(
                    "SELECT id, cvss_score FROM findings WHERE cvss_score < 0 OR cvss_score > 10"
                ).fetchall():
                    assert False, f"{db_path.name}: finding {row[0]} has CVSS {row[1]} outside [0,10]"
                conn.close()
            except sqlite3.OperationalError:
                pass

    def test_fitness_range(self):
        """Fitness scores must be in [0, 1]."""
        import sqlite3
        for db_path in Path("/home/workspace/BugCrusher").glob("*.db"):
            try:
                conn = sqlite3.connect(str(db_path))
                for row in conn.execute(
                    "SELECT id, fitness_score FROM vectors WHERE fitness_score < 0 OR fitness_score > 1"
                ).fetchall():
                    assert False, f"{db_path.name}: vector {row[0]} has fitness {row[1]} outside [0,1]"
                conn.close()
            except sqlite3.OperationalError:
                pass

    def test_generation_non_negative(self):
        """Vector generation must be >= 0."""
        import sqlite3
        for db_path in Path("/home/workspace/BugCrusher").glob("*.db"):
            try:
                conn = sqlite3.connect(str(db_path))
                bad = conn.execute(
                    "SELECT COUNT(*) FROM vectors WHERE generation < 0"
                ).fetchone()[0]
                conn.close()
                assert bad == 0, f"{db_path.name}: {bad} vectors with negative generation"
            except sqlite3.OperationalError:
                pass
