---
name: cloud-strike
description: Automated cloud attack surface mapping for AWS, GCP, Azure. Finds S3 bucket misconfigs, IAM overpermissions, exposed Firebase DBs, open Lambda endpoints, cloud function vulnerabilities, and maps cloud assets to associated domain scopes.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# CLOUD STRIKE — Cloud Attack Surface Orchestrator

**Rule #4: The cloud is where the crown jewels hide.**

Modern infrastructure lives in AWS/GCP/Azure. BugCrusher finds the doors they forgot to lock.

---

## AWS EXPLOITATION FRAMEWORK

```python
class AWSAttackSurface:
    """
    Maps and exploits AWS misconfigurations
    """
    
    ENUMERATION_ORDER = [
        "s3_buckets",        # Often publicly accessible
        "iam_roles",         # Overpermissioned roles
        "lambda_functions",  # Exposed endpoints
        "sns_topics",        # Pub/sub injection
        "sqs_queues",        # Message injection
        "cloudwatch_logs",   # Credential leakage
        "secrets_manager",  # Hardcoded secrets
        "parameter_store",   # Config leakage
        "ec2_metadata",      # IAM role chaining
        "eks_clusters"       # Kubernetes misconfigs
    ]
    
    def scan_s3_public_buckets(self, target_org):
        """
        S3 bucket enumeration - the classic goldmine
        """
        patterns = [
            f"{target_org}-assets",
            f"{target_org}-backups",
            f"{target_org}-logs",
            f"{target_org}-media",
            f"{target_org}-static",
            f"{target_org}-user-uploads",
            f"staging-{target_org}",
            f"dev-{target_org}",
            f"prod-{target_org}",
            f"{target_org}-deployment",
            f"{target_org}-terraform-state"
        ]
        
        findings = []
        for bucket_name in patterns:
            # Check if bucket exists and is accessible
            result = self.check_bucket_acl(bucket_name)
            if result['accessible']:
                findings.append({
                    "type": "PUBLIC_S3_BUCKET",
                    "bucket": bucket_name,
                    "access_level": result['acl'],
                    "severity": self.calculate_severity(result['acl']),
                    "impact": self.assess_bucket_impact(result)
                })
        
        return findings
    
    def check_bucket_acl(self, bucket_name):
        """Check bucket ACL without triggering heavy scans"""
        try:
            # Try unauthenticated listing
            response = self.s3_client.list_objects_v2(
                Bucket=bucket_name,
                MaxKeys=10
            )
            return {
                "accessible": True,
                "acl": "READ",
                "objects": [obj['Key'] for obj in response.get('Contents', [])[:5]]
            }
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == "AccessDenied":
                return {"accessible": True, "acl": "NO_LIST_WRITE_ONLY"}
            elif error_code == "NoSuchBucket":
                return {"accessible": False, "acl": None}
            else:
                return {"accessible": False, "acl": None}
    
    def enumerate_iam_permissions(self, role_name):
        """
        Check what an IAM role can actually do
        """
        # Use IAM simulate to see what actions are permitted
        # Then cross-reference with privilege escalation paths
        pass
    
    def check_ec2_metadata_exposure(self):
        """
        Test if SSRF can hit 169.254.169.254 for IAM credentials
        """
        test_cases = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
        ]
        
        for url in test_cases:
            if self.can_fetch(url):
                return {"vulnerable": True, "provider": self.detect_provider(url)}
        
        return {"vulnerable": False}
```

---

## GCP EXPLOITATION FRAMEWORK

```python
class GCPAttackSurface:
    """
    Google Cloud Platform attack surface mapper
    """
    
    def scan_firebase_realtime_db(self, project_name):
        """
        Firebase databases often left open without auth rules
        """
        firebase_url = f"https://{project_name}.firebaseio.com/.json"
        response = self.http_get(firebase_url)
        
        if response.status == 200:
            return {
                "type": "EXPOSED_FIREBASE_DB",
                "project": project_name,
                "data_accessible": True,
                "data_preview": self.summarize_data(response.json),
                "severity": "CRITICAL"
            }
    
    def scan_open_cloud_functions(self, region):
        """
        GCP Cloud Functions with public access
        """
        functions = self.gcp_client.list_functions(region=region)
        
        public_functions = []
        for func in functions:
            if func.get('httpsTrigger', {}).get('securityLevel') == 'SECURE_OPTIONAL':
                # Test if callable without auth
                if self.can_invoke_without_auth(func['httpsTrigger']['url']):
                    public_functions.append(func)
        
        return public_functions
    
    def check_iam_enumeration(self, project_id):
        """
        Check for overpermissioned service accounts
        """
        # List all service accounts
        # Simulate their permissions
        # Find privilege escalation paths
        pass
```

---

## AZURE EXPLOITATION FRAMEWORK

```python
class AzureAttackSurface:
    """
    Azure cloud attack surface mapper
    """
    
    def scan_storage_accounts(self, resource_group):
        """
        Azure storage accounts with anonymous blob access
        """
        storage_accounts = self.azure_client.list_storage_accounts()
        
        vulnerable_accounts = []
        for account in storage_accounts:
            # Check blob service SAS token policies
            # Check container public access levels
            # Check blob hierarchical namespace settings
            
            containers = self.azure_client.list_containers(account.name)
            for container in containers:
                if container.public_access not in [None, "Off"]:
                    vulnerable_accounts.append({
                        "account": account.name,
                        "container": container.name,
                        "public_access": container.public_access,
                        "severity": "HIGH"
                    })
        
        return vulnerable_accounts
    
    def scan_logic_apps(self):
        """
        Exposed Azure Logic Apps can leak secrets via HTTP headers
        """
        logic_apps = self.azure_client.list_logic_apps()
        
        for app in logic_apps:
            # Check if workflow run history exposes parameters
            # Check if callback URLs are guessable
            pass
    
    def enumerate_keyvault_secrets(self):
        """
        Key Vaults with misconfigured access policies
        """
        # List key vaults
        # Check if managed identity has excessive permissions
        # Check if any secrets are world-readable
        pass
```

---

## CLOUD ASSET → DOMAIN SCOPE MAPPER

```python
class CloudDomainMapper:
    """
    Automatically map cloud infrastructure to domain scope
    """
    
    def map_csp_to_scope(self, target_organization):
        """
        Given an org, find their cloud resources and match to scope
        """
        assets = {
            "aws": self.find_aws_assets(target_organization),
            "gcp": self.find_gcp_assets(target_organization),
            "azure": self.find_azure_assets(target_organization)
        }
        
        # Cross-reference with program scope
        in_scope = []
        for provider, resources in assets.items():
            for resource in resources:
                if self.is_in_scope(resource['domain']):
                    in_scope.append({**resource, "provider": provider})
                else:
                    # Still document for pivot potential
                    pass
        
        return in_scope
```

---

## CLOUD SPECIFIC VULN CHECKLIST

```
AWS CRITICAL FINDS:
├── S3 buckets with public access + sensitive data → CRITICAL ($10K+)
├── IAM role with *:* permissions → CRITICAL
├── EC2 instance with exposed metadata (169.254) via SSRF → CRITICAL
├── Lambda function with overly permissive resource policy → HIGH
├── Secrets Manager with exposed keys → HIGH
└── CloudWatch log groups with leaked credentials → HIGH

GCP CRITICAL FINDS:
├── Firebase DB with no auth rules → CRITICAL
├── Cloud Functions publicly invokable without auth → HIGH
├── Service account key exposure → CRITICAL
├── BigQuery datasets publicly accessible → HIGH
└── Kubernetes clusters with public endpoint + no auth → CRITICAL

AZURE CRITICAL FINDS:
├── Storage account with anonymous blob access → HIGH
├── Logic Apps exposing secrets in URLs → HIGH
├── Key Vault with misconfigured access policies → HIGH
├── App Service with debug enabled → MEDIUM
└── Azure AD privileged role assignments → CRITICAL
```

---

## USAGE

```bash
> cloud-scan target.com --provider aws

BugCrusher responds:
[CLOUD STRIKE] Enumerating AWS attack surface...
[FOUND] 3 S3 buckets in target-org scope
  ├── target-org-backups (public READ) 🔥 CRITICAL
  │   └── Contains: database backups, config files, SSL certs
  ├── target-org-user-uploads (public READ) ⚡ HIGH
  │   └── Contains: user uploaded images, documents
  └── target-org-logs (private, ACL denies listing)
  
[FOUND] IAM role chain opportunity
  └── EC2 instance role has: s3:GetObject, secretsmanager:GetSecret
  
[FOUND] SSRF vector on /upload endpoint
  └── Can hit 169.254.169.254 → steal EC2 role credentials
  
[BOUNTY ESTIMATE] $8,500-$22,000 (P1 in Shopify-like program)
[HUNT PATH] SSRF on /upload → EC2 metadata → S3 bucket read → customer data exposure
```