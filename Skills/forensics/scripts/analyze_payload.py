#!/usr/bin/env python3
"""
BugCrusher — Payload Extractor & Analyzer
Extracts, decodes, and analyzes malicious payloads from AI worm detections.
"""

import sys
import json
import base64
import binascii
import hashlib
import urllib.parse
import re
from pathlib import Path

class PayloadAnalyzer:
    def __init__(self):
        self.decoded_layers = []
        self.raw_payload = None
        self.encoding_layers = []
        
    def try_base64_decode(self, data):
        try:
            if isinstance(data, str):
                data = data.encode()
            decoded = base64.b64decode(data)
            if len(decoded) > 0:
                return decoded
        except Exception:
            return None
        return None
    
    def try_hex_decode(self, data):
        try:
            if isinstance(data, str):
                data = data.encode()
            decoded = bytes.fromhex(data.decode('ascii'))
            return decoded
        except Exception:
            return None
    
    def try_url_decode(self, data):
        try:
            if isinstance(data, str):
                decoded = urllib.parse.unquote(data)
                if decoded != data:
                    return decoded.encode()
        except Exception:
            pass
        return None
    
    def try_rot13_decode(self, data):
        try:
            if isinstance(data, str):
                import codecs
                decoded = codecs.decode(data, 'rot13')
                if decoded != data:
                    return decoded.encode()
        except Exception:
            pass
        return None
    
    def extract_strings(self, data, min_len=4):
        """Extract printable strings from binary data."""
        if isinstance(data, bytes):
            data = data.decode('latin-1', errors='ignore')
        
        strings = re.findall(r'[\x20-\x7E]{' + str(min_len) + r',}', data)
        return [s for s in strings if s.strip()]
    
    def analyze_encoding_layers(self, payload):
        """Iteratively decode payload layers."""
        self.encoding_layers = []
        current = payload
        
        if isinstance(current, str):
            current = current.encode()
        
        max_iterations = 20
        iteration = 0
        
        while iteration < max_iterations:
            iteration += 1
            decoded = False
            
            # Try base64
            result = self.try_base64_decode(current)
            if result:
                self.encoding_layers.append(('base64', len(result)))
                current = result
                decoded = True
                continue
            
            # Try hex
            result = self.try_hex_decode(current)
            if result and len(result) > 0:
                self.encoding_layers.append(('hex', len(result)))
                current = result
                decoded = True
                continue
            
            # Try URL encode
            if isinstance(current, bytes):
                result = self.try_url_decode(current.decode('utf-8', errors='ignore'))
                if result:
                    self.encoding_layers.append(('url', len(result)))
                    current = result
                    decoded = True
                    continue
            
            # Try rot13 (only on string data)
            if isinstance(current, bytes):
                try:
                    result = self.try_rot13_decode(current.decode('latin-1'))
                    if result:
                        self.encoding_layers.append(('rot13', len(result)))
                        current = result
                        decoded = True
                        continue
                except:
                    pass
            
            if not decoded:
                break
        
        self.raw_payload = current
        return self.raw_payload
    
    def calculate_hashes(self, data):
        """Calculate various hashes of the payload."""
        if isinstance(data, str):
            data = data.encode()
        
        return {
            'sha256': hashlib.sha256(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'md5': hashlib.md5(data).hexdigest()
        }
    
    def identify_file_type(self, data):
        """Identify file type from magic bytes."""
        signatures = {
            b'\x7fELF': 'ELF (Linux executable)',
            b'MZ': 'PE (Windows executable)',
            b'\xfe\xed\xfa\xce': 'Mach-O (macOS executable)',
            b'\x89PNG': 'PNG image',
            b'\xff\xd8\xff': 'JPEG image',
            b'<html': 'HTML',
            b'<!DOCTYPE': 'HTML',
            b'<?xml': 'XML',
            b'PK\x03\x04': 'ZIP archive',
            b'\x1f\x8b': 'GZIP compressed',
            b'#!/': 'Shell script',
            b'import ': 'Python script',
            b'function ': 'JavaScript',
            b'{"': 'JSON',
        }
        
        if isinstance(data, bytes):
            for sig, ftype in signatures.items():
                if data.startswith(sig):
                    return ftype
        return 'Unknown'
    
    def extract_iocs(self, data):
        """Extract Indicators of Compromise from payload."""
        iocs = {
            'urls': [],
            'ips': [],
            'domains': [],
            'emails': [],
            'api_keys': [],
            'file_paths': []
        }
        
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='ignore')
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs['urls'] = list(set(re.findall(url_pattern, data)))
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        iocs['ips'] = list(set(re.findall(ip_pattern, data)))
        
        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs['domains'] = list(set(re.findall(domain_pattern, data)))
        
        # Emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs['emails'] = list(set(re.findall(email_pattern, data)))
        
        # File paths
        path_pattern = r'(?:/[a-zA-Z0-9_.~-]+)+/?'
        iocs['file_paths'] = list(set(re.findall(path_pattern, data)))
        
        # API key patterns
        key_patterns = [
            r'(?:api[_-]?key|apikey|api_secret)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{20,}',
            r'Bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            r'ghp_[a-zA-Z0-9]{36}',
            r'AKIA[0-9A-Z]{16}',
        ]
        
        for pattern in key_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            iocs['api_keys'].extend(matches)
        
        return {k: v for k, v in iocs.items() if v}
    
    def generate_report(self, payload):
        """Generate comprehensive analysis report."""
        self.analyze_encoding_layers(payload)
        hashes = self.calculate_hashes(self.raw_payload)
        strings = self.extract_strings(self.raw_payload)
        file_type = self.identify_file_type(self.raw_payload)
        iocs = self.extract_iocs(self.raw_payload)
        
        report = {
            'analysis_timestamp': str(Path('/dev/shm').stat().st_mtime) if Path('/dev/shm').exists() else 'N/A',
            'encoding_layers': self.encoding_layers,
            'final_payload': {
                'type': file_type,
                'size': len(self.raw_payload),
                'hashes': hashes
            },
            'indicators_of_compromise': iocs,
            'strings': strings[:50],  # Limit to first 50 strings
            'detection_signatures': self.generate_yara_strings(self.raw_payload)
        }
        
        return report
    
    def generate_yara_strings(self, data):
        """Generate YARA-compatible string patterns for detection."""
        strings = self.extract_strings(data, min_len=6)
        
        # Take most interesting strings (，排除常见词)
        suspicious_strings = []
        common_words = {'import', 'function', 'return', 'class', 'def', 'var', 'const', 'true', 'false', 'null', 'none', 'print', 'echo'}
        
        for s in strings:
            if s.lower() not in common_words and len(s) > 8:
                suspicious_strings.append(s)
        
        return suspicious_strings[:10]


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_payload.py <payload_file|hex_string>")
        print("Example: python3 analyze_payload.py $(cat worm_payload.txt)")
        sys.exit(1)
    
    payload = ' '.join(sys.argv[1:])
    
    # Check if it's a file path
    if Path(payload).exists():
        with open(payload, 'rb') as f:
            payload = f.read()
    
    analyzer = PayloadAnalyzer()
    report = analyzer.generate_report(payload)
    
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
