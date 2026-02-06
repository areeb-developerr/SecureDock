#!/bin/bash

# Run All Attacks Script
# Executes all attack scripts sequentially and displays Falco log analysis

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FALCO_LOG="$PROJECT_ROOT/falco-logs/output.log"

echo "=========================================="
echo "FALCO SECURITY MONITORING - ATTACK SUITE"
echo "=========================================="
echo ""
echo "This script will run all attack scenarios and analyze Falco logs."
echo "Make sure the webapp and Falco are running!"
echo ""
read -p "Press Enter to continue..."

# Clear previous Falco log (optional - comment out if you want to keep history)
# > "$FALCO_LOG"

echo ""
echo "Step 1: Running benign requests..."
echo "-----------------------------------"
python3 "$SCRIPT_DIR/../attacks/benign_requests.py" || echo "Benign requests script not found, skipping..."

echo ""
echo "Step 2: Running SQL Injection Attack..."
echo "-----------------------------------"
python3 "$SCRIPT_DIR/sql_injection.py"
sleep 2

echo ""
echo "Step 3: Running Path Traversal Attack..."
echo "-----------------------------------"
python3 "$SCRIPT_DIR/path_traversal.py"
sleep 2

echo ""
echo "Step 4: Running Brute Force Attack..."
echo "-----------------------------------"
python3 "$SCRIPT_DIR/brute_force.py"
sleep 2

echo ""
echo "Step 5: Running Command Injection Attack..."
echo "-----------------------------------"
python3 "$SCRIPT_DIR/command_injection.py"
sleep 2

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
    tail -n 50 "$FALCO_LOG" | grep -E "(priority|rule|output)" || tail -n 50 "$FALCO_LOG"
    echo ""
    echo "--- Summary Statistics ---"
    echo "Total log lines: $(wc -l < "$FALCO_LOG")"
    echo "Alerts with 'priority': $(grep -c "priority" "$FALCO_LOG" || echo "0")"
    echo "Alerts with 'Warning': $(grep -c "Warning" "$FALCO_LOG" || echo "0")"
    echo "Alerts with 'Error': $(grep -c "Error" "$FALCO_LOG" || echo "0")"
else
    echo "WARNING: Falco log file not found at $FALCO_LOG"
    echo "Make sure Falco is running and logging to the correct location."
fi

echo ""
echo "=========================================="
echo "ANALYSIS COMPLETE"
echo "=========================================="
echo ""
echo "Review the Falco logs at: $FALCO_LOG"
echo "You can also view logs in real-time with:"
echo "  tail -f $FALCO_LOG"
echo ""

