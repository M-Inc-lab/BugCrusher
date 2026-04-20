#!/usr/bin/env python3
"""Multi-Test Auditor v2 - AST-based audit runner"""
import sys, os, subprocess, re, ast, sqlite3, random
from pathlib import Path
from datetime import datetime

class ASTSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename; self.issues = []
    def visit_Call(self, node):
        fn = ba = None
        if isinstance(node.func, ast.Attribute):
            fn = node.func.attr
            if isinstance(node.func.value, ast.Name): ba = node.func.value.id
        elif isinstance(node.func, ast.Name): fn = node.func.id
        if ba == "subprocess" and fn == "run": self._ck_subprocess(node)
        elif ba in ("os","subprocess") and fn in ("system","popen","execl","execv","spawnl","spawnv"):
            self.issues.append({"severity":"CRITICAL","type":"Cmd Inj: "+ba+"."+fn+"()","line":node.lineno,"snippet":ba+"."+fn+"(...)"})
        elif fn in ("eval","exec") and ba != "ast": self._ck_dangerous(node, fn)
        self.generic_visit(node)
    def _ck_subprocess(self, node):
        sk = next((k for k in node.keywords if k.arg == "shell"), None)
        if not (sk and isinstance(sk.value, ast.Constant) and sk.value.value is True): return
        self.issues.append({"severity":"CRITICAL","type":"Cmd Inj: shell=True","line":node.lineno,"snippet":"subprocess.run(...,shell=True)"})
    def _ck_dangerous(self, node, fn):
        if not node.args:
            self.issues.append({"severity":"CRITICAL","type":"Dangerous "+fn+"()","line":node.lineno,"snippet":fn+"(...)"}); return
        fa = node.args[0]
        if isinstance(fa, ast.Constant):
            val = getattr(fa, "value", None)
            if isinstance(val, str) and len(val) > 5 and re.match(r"^[a-zA-Z0-9+/=]{20,}$", val):
                self.issues.append({"severity":"INFO","type":fn+"() b64 test","line":node.lineno,"snippet":fn+"(<encoded>)"}); return
            return
        self.issues.append({"severity":"CRITICAL","type":"Dangerous "+fn+"(var)","line":node.lineno,"snippet":fn+"(variable)"})

class LogicVisitor(ast.NodeVisitor):
    def __init__(self, fp): self.fp = fp; self.issues = []
    def visit_ExceptHandler(self, node):
        if node.type is None: self.issues.append({"severity":"LOW","type":"Bare except:","line":node.lineno,"snippet":"except:"})
        self.generic_visit(node)
    def visit_FunctionDef(self, node):
        for d,a in zip(reversed(node.args.defaults),reversed(node.args.args)):
            if isinstance(d,(ast.List,ast.Dict,ast.Set)): self.issues.append({"severity":"LOW","type":"Mutable default","line":node.lineno,"snippet":"def "+node.name+"("+a.arg+"=[[]])"})
        self.generic_visit(node)
    visit_AsyncFunctionDef = visit_FunctionDef

class LogicAnalyzer:
    @classmethod
    def analyze_file(cls, fp):
        issues = []
        try:
            src = open(fp).read()
            tree = ast.parse(src)
            visitor = LogicVisitor(fp); visitor.visit(tree); issues.extend(visitor.issues)
            for pat,desc in [
                (r"print\s*\([^)]*%","printf fmt"),
                (r"\s==\sNone\b","==None"),
                (r"for\s+\w+\s+in\s+range\s*\(\s*len\s*\(","range(len)"),
                (r"except\s*:\s*(?:#.*)?$","Bare except"),
            ]:
                for m in re.finditer(pat, src, re.MULTILINE):
                    ln = src[:m.start()].count("\n") + 1
                    issues.append({"severity":"LOW","type":desc,"line":ln,"snippet":m.group()[:50]})
        except: pass
        return issues

class MutationTester:
    def __init__(self):
        self.mutations = [
            ("BareExcept", "def foo():\n    try:\n        pass\nexcept:\n        pass\n"),
            ("PrintfFmt", "def foo():\n    print('val: %s' % 'test')\n"),
            ("EqNone", "def foo():\n    if x == None:\n        pass\n"),
            ("RangeLen", "def foo():\n    for i in range(len(items)):\n        pass\n"),
            ("ShellTrue", "import subprocess\nsubprocess.run('echo hi',shell=True)\n"),
            ("EvalVar", "x = input()\neval(x)\n"),
        ]
    def run(self):
        results = []
        for name, code in self.mutations:
            tmp = "/tmp/mt_"+str(random.randint(1000,9999))+".py"
            open(tmp,"w").write(code)
            try:
                tree = ast.parse(code)
                a = ASTSecurityAnalyzer(tmp); a.visit(tree)
                detected = bool(a.issues or LogicAnalyzer.analyze_file(tmp))
                results.append({"mutation":name,"detected":detected})
            except: results.append({"mutation":name,"detected":False})
            finally:
                if os.path.exists(tmp): os.remove(tmp)
        n = len(results)
        detected = sum(1 for r in results if r["detected"])
        return {"score":detected/n,"details":results,"total":n,"detected":detected}

class MultiTestAuditor:
    PHASES = {1:"Recon",2:"Deps",3:"Tests",4:"DB",5:"Security",6:"Logic",7:"Mutation",8:"Report"}
    def __init__(self, proj, self_audit=False):
        self.project = Path(proj).resolve(); self.self_audit = self_audit
        self.results = {"passed":0,"failed":0,"skipped":0,"errors":0,"security":[],"logic_bugs":[],"boundary":[],"mutation_score":None,"phase_summary":{},"files_analyzed":0}
        self.out = []
    def log(self, msg): print(msg); self.out.append(msg)
    def run(self, phases="1-7"):
        try: active = set(range(int(phases.split("-")[0]),int(phases.split("-")[-1])+1))
        except: active = set(range(1,8))
        self.log("Auditor v2 | " + str(self.project) + " | " + phases)
        if self.self_audit: active.add(7)
        for phase in sorted(active):
            self.log("--- PHASE " + str(phase) + ": " + self.PHASES.get(phase,str(phase)) + " ---")
            try: getattr(self, "phase"+str(phase))()
            except Exception as e: self.log("P"+str(phase)+" ERR: "+str(e))
        self.phase8_report(); return self.out
    def phase1(self):
        py = [f for f in self.project.rglob("*.py") if ".git" not in str(f) and "__pycache__" not in str(f)]
        loc = sum(len(open(f,errors="ignore").readlines()) for f in py)
        self.log("  Files:"+str(len(py))+" LOC:"+str(loc)) 
        self.results["files_analyzed"]=len(py); self.results["phase_summary"]["recon"]={"py_files":len(py),"loc":loc}
    def phase2(self):
        reqs = self.project/"requirements.txt"
        self.log("  OK" if reqs.exists() else "  WARN" + " reqs.txt")
    def phase3(self):
        tfs = list(self.project.rglob("test_*.py"))+list(self.project.rglob("*_test.py"))
        if not tfs: self.results["failed"]=1; self.results["phase_summary"]["tests"]={"status":"FAIL","reason":"no tests"}; self.log("  FAIL: no tests"); return
        if self.self_audit: return
        try:
            r = subprocess.run(["python3","-m","pytest","-v","--tb=short"],cwd=str(self.project),capture_output=True,timeout=120)
            out = r.stdout.decode()+r.stderr.decode()
            p = len(re.findall(r"PASSED",out)); f = len(re.findall(r"FAILED",out))
            self.results["passed"]=p; self.results["failed"]=f; self.results["phase_summary"]["tests"]={"status":"PASS" if f==0 else "FAIL","passed":p,"failed":f}
            self.log("  "+str(p)+" PASS | "+str(f)+" FAIL")
        except Exception as e: self.results["errors"]=1; self.log("  ERR: "+str(e))
    def phase4(self):
        dbs = list(self.project.glob("*.sqlite"))+list(self.project.glob("*.db"))
        if not dbs: self.log("  N/A"); return
        for db in dbs:
            try:
                conn = sqlite3.connect(str(db)); tabs = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]; conn.close()
                self.log("  "+db.name+": "+str(len(tabs))+" tables OK")
            except Exception as e: self.log("  "+db.name+": "+str(e))
    def phase5(self):
        pfs = [f for f in self.project.rglob("*.py") if "multi-test-auditor" not in str(f) and "__pycache__" not in str(f)]
        for pf in pfs:
            try:
                src = open(pf).read(); tree = ast.parse(src)
                a = ASTSecurityAnalyzer(str(pf)); a.visit(tree)
                for iss in a.issues:
                    iss["file"]=str(pf); self.results["security"].append(iss)
                    self.log("  "+iss["severity"]+": "+iss["type"]+" @ "+pf.name+":"+str(iss["line"]))
            except SyntaxError: pass
            except: pass
    def phase6(self):
        pfs = [f for f in self.project.rglob("*.py") if "__pycache__" not in str(f)]
        for pf in pfs:
            for iss in LogicAnalyzer.analyze_file(str(pf)):
                iss["file"]=str(pf); self.results["logic_bugs"].append(iss)
                self.log("  "+iss["severity"]+": "+iss["type"]+" @ "+pf.name+":"+str(iss["line"]))
    def phase7(self):
        t = MutationTester(); r = t.run(); self.results["mutation_score"]=r["score"]
        self.log("  Mut: "+str(r["detected"])+"/"+str(r["total"])+"="+str(round(r["score"]*100))+"%")
        for d in r["details"]:
            status = "OK" if d["detected"] else "MISS"
            self.log("    "+status+": "+d["mutation"])
    def phase8_report(self):
        mut_str = "N/A" if self.results.get("mutation_score") is None else str(round(self.results["mutation_score"]*100))+"%"
        rp = "# Audit Report: "+self.project.name+"\n"
        rp += "**Date:** "+datetime.now().isoformat()+" | **Auditor:** v2\n\n"
        rp += "## Summary\n\n"
        rp += "| Metric | Value |\n|--------|-------|\n"
        rp += "| Files Analyzed | "+str(self.results["files_analyzed"])+" |\n"
        rp += "| Tests | "+str(self.results["passed"])+" PASS / "+str(self.results["failed"])+" FAIL |\n"
        rp += "| Mutation Score | "+mut_str+" |\n"
        rp += "| Security Issues | "+str(len(self.results["security"]))+" |\n"
        rp += "| Logic Bugs | "+str(len(self.results["logic_bugs"]))+" |\n\n"
        rp += "## Security ("+str(len(self.results["security"]))+")\n\n"
        for s in self.results["security"]: rp += "- "+s["severity"]+": "+s["type"]+" L"+str(s.get("line","?"))+"\n"
        rp += "\n## Logic ("+str(len(self.results["logic_bugs"]))+")\n\n"
        for b in self.results["logic_bugs"]: rp += "- "+b["severity"]+": "+b["type"]+" L"+str(b.get("line","?"))+"\n"
        rp += "\n*Multi-Test Auditor v2*\n"
        open(self.project/"AUDIT_REPORT.md","w").write(rp)
        self.log("  Report: "+str(self.project/"AUDIT_REPORT.md"))

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: run_audit.py /path [--phases=1-7] [--self-audit]"); sys.exit(1)
    proj = sys.argv[1]
    sa = "--self-audit" in sys.argv
    auditor = MultiTestAuditor(proj, self_audit=sa)
    auditor.run("1-7")
