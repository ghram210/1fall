#!/usr/bin/env bash

# =============================================================
# Scan System Startup Script
# Starts all 4 tool servers + the gateway غرام
# Usage: bash start.sh
# =============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCAN_DIR="$SCRIPT_DIR/scan-servers"
LOG_DIR="$SCRIPT_DIR/logs"

mkdir -p "$LOG_DIR"

echo "=================================================="
echo "  Penetration Testing Scan System"
echo "=================================================="

# Find Python 3
PYTHON=$(which python3 2>/dev/null)
if [ -z "$PYTHON" ]; then
    echo "[ERROR] Python 3 not found. Please install Python 3"
    exit 1
fi

echo "[*] Using Python: $PYTHON ($($PYTHON --version))"
echo "[*] Installing dependencies (one time setup)..."

# Install with --break-system-packages to bypass Kali restriction
$PYTHON -m pip install --break-system-packages fastapi uvicorn supabase python-dotenv requests -q

# Kill existing servers on these ports (clean restart)
echo "[*] Clearing ports 8001 8002 8003 8004 8080..."
for port in 8001 8002 8003 8004 8080; do
    pid=$(lsof -ti :$port 2>/dev/null || true)
    if [ -n "$pid" ]; then
        kill -9 $pid 2>/dev/null || true
    fi
done

sleep 1

cd "$SCAN_DIR"

# Start Nmap API (port 8001)
echo "[*] Starting Nmap API     -> http://localhost:8001"
$PYTHON -m uvicorn nmap_api:app --host 0.0.0.0 --port 8001 > "$LOG_DIR/nmap.log" 2>&1 &
NMAP_PID=$!

# Start Nikto API (port 8002)
echo "[*] Starting Nikto API    -> http://localhost:8002"
$PYTHON -m uvicorn nikto_api:app --host 0.0.0.0 --port 8002 > "$LOG_DIR/nikto.log" 2>&1 &
NIKTO_PID=$!

# Start SQLmap API (port 8003)
echo "[*] Starting SQLmap API   -> http://localhost:8003"
$PYTHON -m uvicorn sqlmap_api:app --host 0.0.0.0 --port 8003 > "$LOG_DIR/sqlmap.log" 2>&1 &
SQLMAP_PID=$!

# Start FFUF API (port 8004)
echo "[*] Starting FFUF API     -> http://localhost:8004"
$PYTHON -m uvicorn ffuf_api:app --host 0.0.0.0 --port 8004 > "$LOG_DIR/ffuf.log" 2>&1 &
FFUF_PID=$!

# Wait for tool servers to initialize
sleep 2

echo ""
echo "=================================================="
echo "  All tool servers started!"
echo "  Nmap API   -> http://localhost:8001  [log: logs/nmap.log]"
echo "  Nikto API  -> http://localhost:8002  [log: logs/nikto.log]"
echo "  SQLmap API -> http://localhost:8003  [log: logs/sqlmap.log]"
echo "  FFUF API   -> http://localhost:8004  [log: logs/ffuf.log]"
echo ""
echo "  Starting Gateway on port 8080..."
echo "  Press Ctrl+C to stop all servers"
echo "=================================================="
echo ""

# Cleanup on exit
cleanup() {
    echo ""
    echo "[*] Stopping all servers..."
    kill $NMAP_PID $NIKTO_PID $SQLMAP_PID $FFUF_PID 2>/dev/null || true
    pkill -f "uvicorn" 2>/dev/null || true
    echo "[*] All servers stopped."
}
trap cleanup EXIT INT TERM

# Start Gateway in foreground (port 8080)
$PYTHON -m uvicorn gateway:app --host 0.0.0.0 --port 8080