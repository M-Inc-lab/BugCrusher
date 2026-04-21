#!/bin/bash
# BugCrusher v3.5 — Docker Entrypoint
set -e

echo "========================================="
echo " BugCrusher v3.5 — Docker Container"
echo "========================================="

cd /workspace/BugCrusher

# Show status
echo ""
echo "[*] Worm Kill Switch: $(python3 worm_kill_switch.py 2>&1 | grep -o 'CLEAN\|WORM' | head -1)"
echo "[*] Workspace: $WORKSPACE"
echo "[*] Python: $(python3 --version)"
echo ""

# Run hunt engine if target provided
if [ -n "$1" ]; then
    echo "[*] Running hunt on: $1"
    python3 hunt_engine.py "$1"
fi

echo "[*] BugCrusher ready. Connect via web dashboard."

exec "$@"
