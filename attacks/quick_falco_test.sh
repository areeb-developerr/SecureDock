#!/bin/bash

# Quick Falco Detection Test
# Runs a few key attacks that should definitely trigger Falco

echo "=========================================="
echo "QUICK FALCO DETECTION TEST"
echo "=========================================="
echo ""
echo "This script performs 3 key attacks that WILL trigger Falco:"
echo "1. Shell spawning"
echo "2. Sensitive file access"
echo "3. Write to sensitive directory"
echo ""

CONTAINER="dvwa-container"

if ! docker ps --format "{{.Names}}" | grep -q "^${CONTAINER}$"; then
    echo "[!] Container ${CONTAINER} not found. Using first available container..."
    CONTAINER=$(docker ps --format "{{.Names}}" | head -1)
    if [ -z "$CONTAINER" ]; then
        echo "[!] No containers running. Please start containers first."
        exit 1
    fi
    echo "[*] Using container: ${CONTAINER}"
fi

echo "Target container: ${CONTAINER}"
echo ""
read -p "Press Enter to start attacks (monitor Falco logs in another terminal)..."
echo ""

echo "[1] Spawning shell..."
docker exec ${CONTAINER} /bin/sh -c "echo 'Shell spawned - Falco should detect this'"
sleep 2

echo ""
echo "[2] Reading sensitive file /etc/passwd..."
docker exec ${CONTAINER} cat /etc/passwd | head -3
sleep 2

echo ""
echo "[3] Attempting to write to /bin directory..."
docker exec ${CONTAINER} sh -c "echo 'test' > /bin/.test_file 2>&1; rm -f /bin/.test_file 2>&1"
sleep 2

echo ""
echo "=========================================="
echo "ATTACKS COMPLETED"
echo "=========================================="
echo ""
echo "Check Falco logs for detections:"
echo "  tail -f ../falco-logs/output.log"
echo "  docker logs falco-monitor-vulnerable | grep -i 'shell\|sensitive\|write'"
echo ""

