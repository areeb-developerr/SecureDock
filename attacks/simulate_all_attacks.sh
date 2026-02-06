#!/bin/bash
# simulate_all_attacks.sh - Updated for python:slim container
# Automates the simulation of 10 attack patterns for verification

CONTAINER="vulnerable-webapp"
TARGET_URL="http://localhost:5000"

echo "[*] Starting Attack Simulation for 10 Patterns"
echo "[*] Target Container: $CONTAINER"

function run_cmd_in_container() {
    docker exec $CONTAINER sh -c "$1"
    sleep 5
}

# 1. Reverse Shell
echo "--- 1. Simulating REVERSE_SHELL ---"
# Use python to open a socket (outbound connection) after shell spawn
# We don't need a real reverse shell, just the pattern: Shell -> Network
run_cmd_in_container "python3 -c 'import socket; s=socket.socket(); s.connect((\"8.8.8.8\", 53))'"

# 2. Crypto Mining
echo "--- 2. Simulating CRYPTO_MINING ---"
# Pattern: Exec from tmp + Outbound
# We copy a binary to /tmp and rename it to simulate miner, then exec and connect
run_cmd_in_container "cp /bin/ls /tmp/minerd; chmod +x /tmp/minerd; /tmp/minerd >/dev/null; python3 -c 'import urllib.request; urllib.request.urlopen(\"http://google.com\")'"

# 3. Data Exfiltration
echo "--- 3. Simulating DATA_EXFILTRATION ---"
# Pattern: Read Sensitive -> Outbound
run_cmd_in_container "cat /etc/shadow >/dev/null 2>&1; python3 -c 'import urllib.request; urllib.request.urlopen(\"http://google.com\")'"

# 4. Web Shell
echo "--- 4. Simulating WEB_SHELL_INSTALL ---"
# Write to app dir (webroot) and exec
run_cmd_in_container "echo 'print(\"webshell\")' > /app/shell.py; python3 /app/shell.py"

# 5. Privilege Escalation
echo "--- 5. Simulating PRIVILEGE_ESCALATION ---"
# Sudo likely missing, but we can simulate su usage if present, or just access sensitive files
# Falco detects 'su' logic. If su missing, we try to trigger rule keywords in cmdline
run_cmd_in_container "su --help >/dev/null 2>&1; cat /etc/sudoers >/dev/null 2>&1"

# 6. Binary Planting
echo "--- 6. Simulating BINARY_PLANTING ---"
# Write to /usr/bin (might fail if readonly, but typically writable in container as root)
run_cmd_in_container "echo 'malware' > /usr/bin/malware_test; touch /usr/bin/malware_test; rm /usr/bin/malware_test"

# 7. Container Escape
echo "--- 7. Simulating CONTAINER_ESCAPE_RECON ---"
# Read sensitive kernel files
run_cmd_in_container "cat /proc/kcore >/dev/null 2>&1; mount >/dev/null 2>&1"

# 8. Ransomware
echo "--- 8. Simulating RANSOMWARE_BEHAVIOR ---"
# High freq rename
run_cmd_in_container "touch /tmp/r1; mv /tmp/r1 /tmp/r1.enc; touch /tmp/r2; mv /tmp/r2 /tmp/r2.enc; touch /tmp/r3; mv /tmp/r3 /tmp/r3.enc; touch /tmp/r4; mv /tmp/r4 /tmp/r4.enc; touch /tmp/r5; mv /tmp/r5 /tmp/r5.enc"

# 9. Log Tampering
echo "--- 9. Simulating LOG_TAMPERING ---"
run_cmd_in_container "touch /var/log/app_access.log"
run_cmd_in_container "rm /var/log/app_access.log"
run_cmd_in_container "touch /var/log/syslog"
run_cmd_in_container "cat /dev/null > /var/log/syslog" # Truncation

# 10. Recon Spree
echo "--- 10. Simulating RECONNAISSANCE_SPREE ---"
# Some tools might be missing, try common ones
run_cmd_in_container "id; whoami; uname -a; cat /proc/net/tcp 2>/dev/null"

echo "[*] Simulation Complete."
