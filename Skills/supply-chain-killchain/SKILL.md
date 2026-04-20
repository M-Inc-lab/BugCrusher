---
name: supply-chain-killchain
description: Supply chain attack vectors — dependency confusion, typosquatting, malicious CI/CD pipelines, package manager monitoring (npm/PyPI/Go), Git history forensics, and subdomain takeover detection.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# SUPPLY CHAIN KILLCHAIN — Hidden Attack Surface

**Rule #5: Own the dependency, own the build.**

Supply chain attacks are the most valuable, least hunted attack surface in bug bounty.

---

## MODULE 1: DEPENDENCY CONFUSION

```python
class DependencyConfusionHunter:
    """
    Finds packages that exist in multiple registries with different owners
    """
    
    def scan_confusion_targets(self, organization):
        """
        1. Enumerate all internal package names used in org's repos
        2. Check if those names exist in public registries (PyPI, npm, RubyGems)
        3. If public version is HIGHER than internal → potential confusion attack
        """
        internal_packages = self.enumerate_internal_packages(organization)
        
        findings = []
        for pkg in internal_packages:
            public_versions = self.get_public_versions(pkg)
            internal_version = self.get_internal_version(pkg)
            
            if public_versions and internal_version:
                if self.version_greater(public_versions[0], internal_version):
                    findings.append({
                        "type": "DEPENDENCY_CONFUSION",
                        "package": pkg,
                        "internal_version": internal_version,
                        "public_version": public_versions[0],
                        "risk": "HIGH",
                        "exploit": f"Publish malicious package to {pkg} → all builds pull malware"
                    })
        
        return findings
```

---

## MODULE 2: TYPOSQUATTING DETECTION

```python
class TyposquatHunter:
    """
    Find malicious packages with names similar to popular ones
    """
    
    def generate_typosquat_candidates(self, package_name):
        """
        Generate common typo variations
        """
        variations = []
        
        # Character addition
        for i in range(len(package_name)):
            for c in string.ascii_lowercase:
                variations.append(package_name[:i] + c + package_name[i:])
        
        # Character deletion
        for i in range(len(package_name)):
            variations.append(package_name[:i] + package_name[i+1:])
        
        # Character substitution
        similar_chars = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$'}
        for char, replacement in similar_chars.items():
            variations.append(package_name.replace(char, replacement))
        
        # Homoglyph attacks ( Cyrillic 'а' vs Latin 'a' )
        variations.extend(self.homoglyph_variants(package_name))
        
        return variations
    
    def check_typosquat_on_registries(self, package_name):
        """Check if typosquat variant exists in npm/PyPI"""
        candidates = self.generate_typosquat_candidates(package_name)
        
        existing = []
        for variant in candidates:
            if self.package_exists("npm", variant):
                existing.append({"registry": "npm", "package": variant})
            if self.package_exists("pypi", variant):
                existing.append({"registry": "PyPI", "package": variant})
        
        return existing
```

---

## MODULE 3: CI/CD PIPELINE FORENSICS

```python
class CICDPipelineHunter:
    """
    Find exposed CI/CD configurations and secrets
    """
    
    def scan_github_actions_leaks(self, organization):
        """
        Find workflows with hardcoded secrets
        """
        workflows = self.github_client.get_workflows(organization)
        
        findings = []
        for repo, workflow in workflows:
            if workflow.get('trigger', {}).get('schedule'):
                # Cron jobs = often have secrets in env
                pass
            
            # Check for secrets in env vars
            for job_name, job in workflow['jobs'].items():
                for step in job.get('steps', []):
                    env = step.get('env', {})
                    secrets = self.detect_secrets_in_dict(env)
                    if secrets:
                        findings.append({
                            "type": "CI/CD_SECRET_EXPOSURE",
                            "repo": repo,
                            "workflow": workflow['path'],
                            "job": job_name,
                            "step": step['name'],
                            "secrets": secrets,
                            "severity": "CRITICAL"
                        })
    
    def check_jenkins_instances(self, target):
        """
        Find open Jenkins instances that expose job configs
        """
        jenkins_urls = [
            f"https://{target}/jenkins/api/json",
            f"https://jenkins.{target}/api/json",
            f"http://{target}:8080/api/json"
        ]
        
        for url in jenkins_urls:
            response = self.http_get(url)
            if response.status == 200 and "jobs" in response.json():
                return {
                    "type": "EXPOSED_JENKINS",
                    "url": url,
                    "jobs_count": len(response.json()['jobs']),
                    "severity": "HIGH"
                }
```

---

## MODULE 4: GIT HISTORY FORENSICS

```python
class GitHistoryForensics:
    """
    Search historical commits for buried secrets and backdoors
    """
    
    SECRET_PATTERNS = [
        r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']',
        r'secret[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']',
        r'password["\']?\s*[:=]\s*["\'][A-Za-z0-9@#$]{8,}["\']',
        r'aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\'][A-Z0-9]{16,}["\']',
        r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        r'ghp_[A-Za-z0-9]{36}',  # GitHub personal token
        r'xox[baprs]-[A-Za-z0-9]{10,}'  # Slack tokens
    ]
    
    def scan_repo_for_secrets(self, repo_url):
        """
        Clone and scan all git history for secrets
        """
        clone_dir = self.clone_repo(repo_url)
        
        findings = []
        for commit in self.iterate_commits(clone_dir):
            diff = self.get_commit_diff(clone_dir, commit)
            for pattern in self.SECRET_PATTERNS:
                matches = re.findall(pattern, diff)
                if matches:
                    findings.append({
                        "commit": commit.hash,
                        "author": commit.author,
                        "date": commit.date,
                        "pattern": pattern,
                        "match": matches[0][:50],
                        "file": self.get_changed_files(commit)[0]
                    })
        
        return findings
    
    def find_removed_secrets(self, repo_url):
        """
        Find secrets that were committed and then removed (still in history)
        """
        # Check commits where secret was removed but still exists in history
        pass
    
    def detect_backdoor_commits(self, repo_url):
        """
        Find commits with suspicious patterns (obfuscated code, base64 blobs)
        """
        suspicious_patterns = [
            "eval(atob(",  # Obfuscated JS
            "exec(base64",  # Base64 encoded execution
            "system($_GET",  # PHP webshell pattern
            "Runtime.exec",  # Java command injection
            "__import__('os').system"  # Python RCE
        ]
        
        findings = []
        for commit in self.iterate_commits(repo_url):
            for pattern in suspicious_patterns:
                if self.commit_contains(commit, pattern):
                    findings.append({
                        "commit": commit.hash,
                        "pattern": pattern,
                        "author": commit.author
                    })
        
        return findings
```

---

## MODULE 5: SUBDOMAIN TAKEOVER DETECTION

```python
class SubdomainTakeoverHunter:
    """
    Find dangling DNS records pointing to decommissioned resources
    """
    
    VULNERABLE_SERVICES = {
        "github.io": {
            "check": lambda host: self.check_github_pages_404(host),
            "pattern": r"\.(herokuapp|cloudfront|azurewebsites|aws|elasticbeanstalk)\.com"
        },
        "readthedocs.io": {
            "check": lambda host: self.check_rtd_404(host)
        },
        "surge.sh": {
            "check": lambda host: self.check_surge_404(host)
        },
        "now.sh": {
            "check": lambda host: self.check_zeit_now_404(host)
        },
        "wordpress.com": {
            "check": lambda host: self.check_wp_404(host)
        },
        "amazonaws.com": {
            "check": lambda host: self.check_elasticbeanstalk_404(host)
        }
    }
    
    def detect_takeover_candidates(self, subdomains):
        """
        For each subdomain, check if it points to decommed service
        """
        findings = []
        
        for subdomain in subdomains:
            dns_record = self.get_dns_record(subdomain)
            
            # Check for CNAME pointing to vulnerable services
            cname = dns_record.get('cname', '')
            for service, config in self.VULNERABLE_SERVICES.items():
                if service in cname:
                    is_takeover = config['check'](subdomain)
                    if is_takeover:
                        findings.append({
                            "type": "SUBDOMAIN_TAKEOVER",
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": service,
                            "severity": "HIGH",
                            "exploit": f"Register {service} account → claim subdomain → serve malicious content"
                        })
        
        return findings
```

---

## SUPPLY CHAIN ATTACK CHECKLIST

```
EXPLOITABLE VECTORS:
├── Dependency Confusion → PyPI/npm package with higher version
├── Typosquatting → Malicious package with similar name to popular lib
├── CI/CD Secrets → Hardcoded tokens in GitHub Actions/Jenkins
├── Git History Secrets → Leaked keys buried in old commits
├── Backdoor Commits → Obfuscated code in third-party deps
├── Subdomain Takeover → Dangling DNS to decommed services
└── Malicious Code Injection → Typosquatting popular build tools (webpack, etc)
```

---

## USAGE

```bash
> supply-chain-scan target-org --target npm,github,aws

BugCrusher responds:
[SUPPLY CHAIN KILLCHAIN] Scanning for hidden attack vectors...
[FOUND] 3 exposed secrets in GitHub history
  ├── aws_secret_key in commit abc123 (removed 3 years ago but still in history)
  ├── GitHub PAT in jenkins-pipeline.yml (still active)
  └── Slack webhook in .github/workflows/deploy.yml (still valid)
  
[FOUND] 2 subdomain takeover candidates
  ├── staging-legacy.target.com → points to *.herokuapp.com (NOT PWNED YET)
  └── dev-backup.target.com → points to *.aws.amazon.com (NOT PWNED YET)
  
[FOUND] Dependency confusion opportunity
  ├── Internal package: @target-org/utils@1.0.0
  └── Public PyPI has no @target-org/utils (can claim it!)
  
[BOUNTY ESTIMATE] $5,000-$15,000 (critical asset exposure)
[HUNT PATH] Claim @target-org/utils → wait for internal CI/CD to pull → inject malicious code → supply chain compromise
```