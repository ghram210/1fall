#!/usr/bin/env bash

# =============================================================
# Scan System Startup Script
# Starts all 4 tool servers + the gateway
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

$PYTHON -m pip install --break-system-packages fastapi uvicorn supabase python-dotenv requests httpx -q 2>/dev/null || true

# Kill existing servers on these ports (clean restart)
echo "[*] Clearing ports 8001 8002 8003 8004 8090..."
for port in 8001 8002 8003 8004 8090; do
    pid=$(lsof -ti :$port 2>/dev/null || true)
    if [ -n "$pid" ]; then
        kill -9 $pid 2>/dev/null || true
    fi
done

sleep 1

cd "$SCAN_DIR"

# Start Nmap API (port 8001) — stream to terminal AND log
echo "[*] Starting Nmap API     -> http://localhost:8001"
( $PYTHON -u -m uvicorn nmap_api:app --host 0.0.0.0 --port 8001 2>&1 | sed -u 's/^/[NMAP-SRV] /' | tee "$LOG_DIR/nmap.log" ) &
NMAP_PID=$!

# Start Nikto API (port 8002)
echo "[*] Starting Nikto API    -> http://localhost:8002"
( $PYTHON -u -m uvicorn nikto_api:app --host 0.0.0.0 --port 8002 2>&1 | sed -u 's/^/[NIKTO-SRV] /' | tee "$LOG_DIR/nikto.log" ) &
NIKTO_PID=$!

# Start SQLmap API (port 8003)
echo "[*] Starting SQLmap API   -> http://localhost:8003"
( $PYTHON -u -m uvicorn sqlmap_api:app --host 0.0.0.0 --port 8003 2>&1 | sed -u 's/^/[SQLMAP-SRV] /' | tee "$LOG_DIR/sqlmap.log" ) &
SQLMAP_PID=$!

# Start FFUF API (port 8004)
echo "[*] Starting FFUF API     -> http://localhost:8004"
( $PYTHON -u -m uvicorn ffuf_api:app --host 0.0.0.0 --port 8004 2>&1 | sed -u 's/^/[FFUF-SRV] /' | tee "$LOG_DIR/ffuf.log" ) &
FFUF_PID=$!

# Wait for tool servers to initialize
sleep 3

# Verify tool servers started
echo ""
echo "[*] Checking tool servers..."
for port in 8001 8002 8003 8004; do
    if curl -s "http://localhost:$port/health" > /dev/null 2>&1; then
        echo "    [OK] Port $port is responding"
    else
        echo "    [WARN] Port $port not responding yet (may still be starting)"
    fi
done

echo ""
echo "=================================================="
echo "  All tool servers started!"
echo "  Nmap API   -> http://localhost:8001  [log: logs/nmap.log]"
echo "  Nikto API  -> http://localhost:8002  [log: logs/nikto.log]"
echo "  SQLmap API -> http://localhost:8003  [log: logs/sqlmap.log]"
echo "  FFUF API   -> http://localhost:8004  [log: logs/ffuf.log]"
echo ""
echo "  Starting Gateway on port 8090..."
echo "  Express API should run separately on port 8080"
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

# Start Gateway in foreground (port 8090)
$PYTHON -m uvicorn gateway:app --host 0.0.0.0 --port 8090
