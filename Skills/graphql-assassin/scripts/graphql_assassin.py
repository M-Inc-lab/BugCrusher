#!/usr/bin/env python3
"""
BugCrusher - GraphQL Assassin
Deep GraphQL testing: introspection enum, batch attacks, alias buster, etc.
"""
import requests
import json
import re
import time
from datetime import datetime
from typing import List, Dict, Optional

class GraphQLAssassin:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        if not "/graphql" in target:
            self.endpoint = f"{self.target}/graphql"
        else:
            self.endpoint = target
            self.target = re.sub(r"/graphql.*", "", target)
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self.findings = []
    
    def introspect(self) -> Dict:
        """Full schema introspection."""
        query = {"query": "{ __schema { types { name kind description fields { name type { name kind } } } } }"}
        try:
            r = self.session.post(self.endpoint, json=query, timeout=15)
            if r.status_code == 200:
                data = r.json().get("data", {})
                types = data.get("__schema", {}).get("types", [])
                self.findings.append({"type": "introspection", "severity": "INFO", 
                    "desc": f"Schema enumerated: {len(types)} types found", "data": types})
                return data
        except Exception as e:
            self.findings.append({"type": "introspection", "severity": "ERROR", "desc": str(e)})
        return {}
    
    def batch_attack(self, query_template: str, iterations: int = 100) -> Dict:
        """Batch query attack - extract data beyond rate limits."""
        batch = [{"id": i, "json": {"query": query_template}} for i in range(iterations)]
        start = time.time()
        try:
            r = self.session.post(self.endpoint, json=batch, timeout=30)
            elapsed = time.time() - start
            if r.status_code == 200:
                responses = r.json()
                if isinstance(responses, list):
                    self.findings.append({"type": "batch_attack", "severity": "HIGH",
                        "desc": f"Batch accepted: {len(responses)} responses in {elapsed:.2f}s - rate limit bypassed", "count": len(responses)})
                    return {"bypassed": True, "responses": len(responses), "time": elapsed}
        except Exception as e:
            self.findings.append({"type": "batch_attack", "severity": "ERROR", "desc": str(e)})
        return {"bypassed": False}
    
    def alias_abuse(self, field: str, count: int = 100) -> Dict:
        """Alias-based rate limit bypass - duplicate same field."""
        alias_query = " ".join([f"alias{i}: {field}" for i in range(count)])
        query = {"query": f"{{ {alias_query} }}"}
        try:
            r = self.session.post(self.endpoint, json=query, timeout=15)
            if r.status_code == 200:
                data = r.json()
                if "errors" not in data:
                    self.findings.append({"type": "alias_bypass", "severity": "HIGH",
                        "desc": f"Alias bypass worked: {count} fields in 1 request - rate limit circumvented", "count": count})
                    return {"bypassed": True, "aliases": count}
        except Exception as e:
            self.findings.append({"type": "alias_bypass", "severity": "ERROR", "desc": str(e)})
        return {"bypassed": False}
    
    def field_duplication(self, query: str) -> Dict:
        """Duplicate fields to extract additional data via resolver mismatch."""
        duped = re.sub(r'(\w+)\s*\{', lambda m: m.group(0) + m.group(0), query)
        query = {"query": duped}
        try:
            r = self.session.post(self.endpoint, json=query, timeout=15)
            if r.status_code == 200:
                self.findings.append({"type": "field_duplication", "severity": "MEDIUM",
                    "desc": "Field duplication attempted - tests resolver inconsistencies", "status": r.status_code})
        except:
            pass
        return {"tested": True}
    
    def trace_test(self) -> Dict:
        """Test for apollo-trace potential information disclosure."""
        headers = {"X-Apollo-Tracing": "1"}
        try:
            r = self.session.post(self.endpoint, json={"query": "{ __typename }"}, headers=headers, timeout=10)
            if "X-Trace-Id" in r.headers or "apollo-tracing" in r.text:
                self.findings.append({"type": "trace_enabled", "severity": "MEDIUM",
                    "desc": "Apollo tracing enabled - potential internal architecture disclosure"})
                return {"exposed": True}
        except:
            pass
        return {"exposed": False}
    
    def sdl_enum(self) -> List[str]:
        """Enumerate available types via SDL probe."""
        types = []
        probes = ["User", "Admin", "Query", "Mutation", "Subscription", "String", "Int", "Boolean", 
                  "Float", "ID", "DateTime", "UUID", "JSON", "Upload", "Pagination", "Connection"]
        for t in probes:
            query_str = "{ __type(name: \\\"" + t + "\\\") { name kind } }"; query = {"query": query_str}
            try:
                r = self.session.post(self.endpoint, json=query, timeout=5)
                if r.status_code == 200 and "null" not in r.text:
                    types.append(t)
            except:
                pass
        if types:
            self.findings.append({"type": "sdl_enum", "severity": "INFO",
                "desc": f"SDL enumeration found types: {types}", "types": types})
        return types
    
    def full_assault(self) -> Dict:
        """Run full GraphQL attack suite."""
        print(f"[*] GraphQL Assassin: {self.endpoint}")
        results = {
            "endpoint": self.endpoint, "timestamp": datetime.now().isoformat(),
            "schema": self.introspect() != {},
            "sdl_types": self.sdl_enum(),
            "trace": self.trace_test(),
            "batch": self.batch_attack("{ __typename }"),
            "alias": self.alias_abuse("__typename", 50),
            "findings": self.findings
        }
        print(f"[*] Findings: {len(self.findings)}")
        for f in self.findings:
            print(f"  [{f['severity']}] {f['type']}: {f['desc']}")
        return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python graphql_assassin.py <endpoint> [--introspect|--batch|--alias|--sdl]")
        sys.exit(1)
    target = sys.argv[1]
    assassin = GraphQLAssassin(target)
    mode = sys.argv[2] if len(sys.argv) > 2 else "--full"
    if mode == "--introspect":
        r = assassin.introspect()
    elif mode == "--batch":
        r = assassin.batch_attack("{ __typename }")
    elif mode == "--alias":
        r = assassin.alias_abuse("__typename", 50)
    elif mode == "--sdl":
        r = assassin.sdl_enum()
    else:
        r = assassin.full_assault()
    print(json.dumps(r, indent=2, default=str))
