#!/usr/bin/env python3
"""
BINARY-RECON — Binary Exploitation Framework
Run: python3 Skills/binary-recon/scripts/binary_recon.py <binary_path> <action>
Actions: rop, fmt, heap, disasm, analyze
"""
import sys, os, subprocess, shlex

TOOLS = {'ropper': 'ropper', 'objdump': 'objdump', 'radare2': 'radare2', 'gdb': 'gdb'}

def check_binary(path):
    if not os.path.exists(path):
        print(f"[!] Binary not found: {path}")
        return False
    print(f"[*] Analyzing: {path}")
    return True

def rop_chain(binary):
    print("[*] Building ROP chain...")
    try:
        r = subprocess.run(['ropper', '-f', binary, '--search', 'pop'], 
                          capture_output=True, text=True, timeout=30)
        gadgets = [l for l in r.stdout.split('\n') if 'gadget' in l.lower()][:20]
        print(f"[*] Found {len(gadgets)} ROP gadgets")
        return gadgets
    except Exception as e:
        return [f"ropper failed: {e}"]

def format_string(binary):
    print("[*] Format string attack vector...")
    return ["%s%p%x%n%99999x", "%x%x%x%x%x%x%x%x", "${ENV_VAR}", "@@GLOBALS@@"]

def heap_exploit(binary):
    print("[*] Heap exploitation vectors...")
    return ["\x00" * 100 + "A" * 8 + "\xef\xbe\xad\xde", "chunk overflow test"]

def analyze_binary(binary):
    print("[*] Full binary analysis...")
    results = {
        'arch': subprocess.run(['file', binary], capture_output=True, text=True).stdout.strip(),
        'symbols': subprocess.run(['nm', binary], capture_output=True, text=True).stdout.split('\n')[:50],
        'sections': subprocess.run(['readelf', '-S', binary], capture_output=True, text=True).stdout.split('\n')[:30]
    }
    return results

def main():
    if len(sys.argv) < 3:
        print("Usage: binary_recon.py <binary_path> <action>")
        sys.exit(1)
    
    binary, action = sys.argv[1], sys.argv[2]
    if not check_binary(binary):
        sys.exit(1)
    
    if action == 'rop':
        print('\n'.join(rop_chain(binary)))
    elif action == 'fmt':
        print('\n'.join(format_string(binary)))
    elif action == 'heap':
        print('\n'.join(heap_exploit(binary)))
    elif action == 'analyze':
        for k, v in analyze_binary(binary).items():
            print(f"=== {k.upper()} ===")
            print(v[:500] if isinstance(v, str) else v)
    else:
        print(f"[!] Unknown action: {action}")
        sys.exit(1)

if __name__ == '__main__':
    main()