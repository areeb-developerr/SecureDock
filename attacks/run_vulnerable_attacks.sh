#!/bin/bash

# Run Attacks on Vulnerable Containers
# Tests Falco detection on real vulnerable applications

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FALCO_LOG="$PROJECT_ROOT/falco-logs/output.log"

echo "=========================================="
echo "FALCO DETECTION TEST - VULNERABLE CONTAINERS"
echo "=========================================="
echo ""
echo "This script will:"
echo "1. Start vulnerable containers (DVWA, Juice Shop)"
echo "2. Run attack scripts against them"
echo "3. Monitor Falco logs for detections"
echo ""
read -p "Press Enter to continue..."

# Clear previous Falco log
> "$FALCO_LOG" 2>/dev/null || true

echo ""
echo "Step 1: Starting vulnerable containers..."
echo "-----------------------------------"
cd "$PROJECT_ROOT/docker"
docker-compose -f docker-compose-vulnerable.yml up -d

echo ""
echo "Waiting for containers to be ready..."
sleep 10

# Check if containers are running
echo ""
echo "Container Status:"
docker-compose -f docker-compose-vulnerable.yml ps

echo ""
echo "Step 2: Testing DVWA..."
echo "-----------------------------------"
cd "$SCRIPT_DIR"
python3 attack_dvwa.py
sleep 3

echo ""
echo "Step 3: Testing Juice Shop..."
echo "-----------------------------------"
python3 attack_juice_shop.py
sleep 3

echo ""
echo "Step 4: Performing direct container attacks..."
echo "-----------------------------------"

# Direct command execution in containers
echo "[*] Executing commands in DVWA container..."
docker exec dvwa-container sh -c "ls -la /" 2>&1 | head -5
docker exec dvwa-container sh -c "cat /etc/passwd" 2>&1 | head -3
docker exec dvwa-container sh -c "whoami" 2>&1

echo ""
echo "[*] Executing commands in Juice Shop container..."
docker exec juice-shop-container sh -c "ls -la /" 2>&1 | head -5
docker exec juice-shop-container sh -c "ps aux" 2>&1 | head -3

sleep 3

echo ""
echo "=========================================="
echo "ATTACKS COMPLETED"
echo "=========================================="
echo ""
echo "Analyzing Falco logs..."
echo ""

if [ -f "$FALCO_LOG" ]; then
    echo "Falco Log Location: $FALCO_LOG"
    echo ""
    echo "--- Recent Falco Alerts (last 50 lines) ---"
    tail -n 50 "$FALCO_LOG" | head -30
    echo ""
    echo "--- Summary Statistics ---"
    echo "Total log lines: $(wc -l < "$FALCO_LOG" 2>/dev/null || echo "0")"
    
    # Try to parse JSON logs
    if command -v jq &> /dev/null; then
        echo "Alerts with priority: $(grep -c "priority" "$FALCO_LOG" 2>/dev/null || echo "0")"
        echo "Warning level alerts: $(grep -c "Warning" "$FALCO_LOG" 2>/dev/null || echo "0")"
        echo "Error level alerts: $(grep -c "Error" "$FALCO_LOG" 2>/dev/null || echo "0")"
    fi
else
    echo "WARNING: Falco log file not found at $FALCO_LOG"
    echo "Checking Falco container logs..."
    docker logs falco-monitor-vulnerable 2>&1 | tail -20
fi

echo ""
echo "=========================================="
echo "ANALYSIS COMPLETE"
echo "=========================================="
echo ""
echo "Review the Falco logs at: $FALCO_LOG"
echo "View real-time logs with: tail -f $FALCO_LOG"
echo ""
echo "To stop containers:"
echo "  cd $PROJECT_ROOT/docker"
echo "  docker-compose -f docker-compose-vulnerable.yml down"
echo ""

