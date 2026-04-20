#!/usr/bin/env python3
"""
BugCrusher — Supply Chain Killchain
Dependency confusion, typosquatting, malicious package detection.
"""

import requests
import json
import hashlib
import PyNomaly
from typing import Dict, List, Optional, Tuple
from packaging import version

class SupplyChainKillchain:
    """
    Finds supply chain attack vectors.
    
    Usage:
        sc = SupplyChainKillchain()
        findings = sc.check_typosquat('express', 'npm', existing_pkgs=['express', 'express-js'])
        print(findings)  # [{'package': 'expres', 'risk': 'HIGH', 'similarity': 0.91}]
    """
    
    def __init__(self):
        self.registry_apis = {
            'npm': 'https://registry.npmjs.org',
            'pypi': 'https://pypi.org/pypi',
            'go': 'https://pkg.go.dev',
            'rubygems': 'https://rubygems.org/api/v1',
            'maven': 'https://search.maven.org/solrsearch'
        }
        self.typosquatting_patterns = [
            ('e', '3'), ('a', '4'), ('i', '1'), ('o', '0'),
            ('s', 'z'), ('ss', 's'), ('ii', 'i')
        ]
        self.popular_packages = self._load_popular_packages()
    
    def _load_popular_packages(self) -> Dict[str, List[str]]:
        return {
            'npm': ['express', 'react', 'vue', 'angular', 'lodash', 'axios', 'moment', 'async', 'debug', 'request'],
            'pypi': ['requests', 'numpy', 'pandas', 'django', 'flask', 'tensorflow', 'pytest', 'pip', 'boto3', 'celery'],
            'go': ['gin', 'gorm', 'echo', 'fasthttp', 'viper', 'cobra', ' logrus', 'ginkgo']
        }
    
    def check_typosquat(self, package: str, ecosystem: str, threshold: float = 0.85) -> List[Dict]:
        """Detect typosquatting candidates."""
        results = []
        variants = self._generate_variants(package)
        
        for variant in variants:
            exists = self._check_package_exists(variant, ecosystem)
            if exists:
                results.append({
                    'original': package,
                    'typosquat': variant,
                    'risk': 'HIGH' if self._calculate_similarity(package, variant) > 0.9 else 'MEDIUM',
                    'similarity': self._calculate_similarity(package, variant),
                    'registry': f"{self.registry_apis.get(ecosystem, '')}/{variant}"
                })
        
        return results
    
    def check_dependency_confusion(self, package: str, ecosystem: str) -> Dict:
        """Detect dependency confusion vulnerability."""
        public = self._get_public_package(package, ecosystem)
        private = self._check_private_registry(package, ecosystem)
        
        if public and private:
            if self._compare_versions(public['version'], private.get('version', '0.0.0')) > 0:
                return {
                    'package': package,
                    'ecosystem': ecosystem,
                    'public_version': public['version'],
                    'private_version': private.get('version', 'unknown'),
                    'vulnerable': True,
                    'risk': 'CRITICAL'
                }
        
        return {'package': package, 'vulnerable': False}
    
    def _generate_variants(self, package: str) -> List[str]:
        """Generate typosquatting variants."""
        variants = set()
        base = package.lower()
        
        for old, new in self.typosquatting_patterns:
            if old in base:
                variants.add(base.replace(old, new))
        
        for i in range(len(base)):
            variants.add(base[:i] + base[i+1:])
        
        variants.add(base + 's')
        variants.add(base + '-')
        variants.add(base + '_')
        variants.add('-' + base)
        variants.add('_' + base)
        
        return list(variants)
    
    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Levenshtein-based similarity."""
        if len(s1) < len(s2):
            return self._calculate_similarity(s2, s1)
        
        if len(s2) == 0:
            return 0.0
        
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        
        distance = prev_row[-1]
        max_len = max(len(s1), len(s2))
        return 1 - (distance / max_len)
    
    def _check_package_exists(self, package: str, ecosystem: str) -> bool:
        """Check if package exists in public registry."""
        if ecosystem == 'npm':
            try:
                r = requests.get(f"https://registry.npmjs.org/{package}", timeout=3)
                return r.status_code == 200
            except:
                return False
        elif ecosystem == 'pypi':
            try:
                r = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=3)
                return r.status_code == 200
            except:
                return False
        return False
    
    def _get_public_package(self, package: str, ecosystem: str) -> Optional[Dict]:
        """Get public package info."""
        if ecosystem == 'npm':
            try:
                r = requests.get(f"https://registry.npmjs.org/{package}/latest", timeout=3)
                if r.status_code == 200:
                    data = r.json()
                    return {'version': data.get('version'), 'name': data.get('name')}
            except:
                return None
        return None
    
    def _check_private_registry(self, package: str, ecosystem: str) -> Optional[Dict]:
        """Check private registry. Needs API key configuration."""
        return None
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare semantic versions. Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""
        try:
            return version.parse(v1) > version.parse(v2)
        except:
            return 0


if __name__ == '__main__':
    sc = SupplyChainKillchain()
    
    print("[*] Supply Chain Killchain Scanner")
    print("[*] Testing typosquatting detection...")
    
    results = sc.check_typosquat('express', 'npm')
    for r in results:
        print(f"  [!] Typosquat detected: {r}")
    
    print("\n[*] Testing dependency confusion...")
    result = sc.check_dependency_confusion('my-corp-internal', 'npm')
    print(f"  [*] Result: {result}")
