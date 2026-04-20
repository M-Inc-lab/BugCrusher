---
name: mobile-nexus
description: Mobile application security testing for Android (APK reversing, runtime analysis, SSL pinning bypass, insecure storage detection) and iOS (IPA analysis, runtime manipulation, keychain extraction). Covers API attacks on mobile backends.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# MOBILE NEXUS — Mobile App Attack Framework

**Rule #6: The phone is the target AND the gateway.**

Mobile apps expose attack surface that web testing never sees.

---

## ANDROID EXPLOITATION FRAMEWORK

### APK Reverse Engineering Pipeline

```python
class AndroidPenTest:
    """
    Full Android penetration testing pipeline
    """
    
    def extract_apk(self, apk_path):
        """Use apktool, jadx, and frida to decompile and analyze"""
        return {
            'manifest': self.parse_android_manifest(apk_path),
            'activities': self.enumerate_activities(apk_path),
            'services': self.enumerate_services(apk_path),
            'receivers': self.enumerate_broadcast_receivers(apk_path),
            'providers': self.enumerate_content_providers(apk_path),
            'permissions': self.map_permission_elevation_paths(apk_path),
            'deeplinks': self.extract_uri_schemes(apk_path),
            'hardcoded_secrets': self.extract_hardcoded_credentials(apk_path),
            'crypto_impl': self.analyze_crypto_misuse(apk_path),
            'ssl_pinning': self.check_certificate_pinning(apk_path),
            'insecure_storage': self.find_data_exposure_points(apk_path),
            'intent_sniffing': self.map_inter_process_communication(apk_path),
        }
    
    def find_ssrf_via_deeplinks(self, apk_data):
        """Deep links can trigger SSRF from mobile apps"""
        ssrf_patterns = [
            r'(https?://[^\s\"\']+)',
            r'content://[^\s\"\']+',
            r'file://[^\s\"\']+',
        ]
        # Test every extracted URL pattern against internal endpoints
```

---

## IOS EXPLOITATION FRAMEWORK

```python
class iOSPenTest:
    """
    iOS penetration testing with objection + frida
    """
    
    def runtime_analysis(self, app_bundle_id):
        """Hook Objective-C/Swift runtime to extract secrets"""
        hooks = [
            "NSUR