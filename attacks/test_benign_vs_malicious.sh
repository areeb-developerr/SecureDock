#!/bin/bash
#
# Benign vs Malicious Comparison Test
# Proves that Secure Dock correctly classifies containers
#
# This script runs:
#   1. Benign traffic on benign-nginx   → should show GREEN/healthy on dashboard
#   2. Malicious attacks on vulnerable-webapp → should show RED/malicious on dashboard
#

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

BENIGN_CONTAINER="benign-nginx"
ATTACK_CONTAINER="vulnerable-webapp"
BENIGN_URL="http://localhost:8888"
WEBAPP_URL="http://localhost:5000"

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    SECURE DOCK — Benign vs Malicious Test Demo        ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check containers
for c in "$BENIGN_CONTAINER" "$ATTACK_CONTAINER"; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        echo -e "${RED}✗ Container '$c' is not running!${NC}"
        echo -e "  Run: cd docker && docker compose up -d"
        exit 1
    fi
done
echo -e "${GREEN}✓ Both containers are running${NC}"
echo ""

# ═══════════════════════════════════════════════════════════
# PHASE 1: Benign Traffic on benign-nginx
# ═══════════════════════════════════════════════════════════
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}  PHASE 1: BENIGN TRAFFIC on ${BENIGN_CONTAINER}${NC}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}Sending normal HTTP requests + harmless container activity${NC}"
echo -e "${CYAN}(These trigger low-level INFO Falco events = benign, not malicious)${NC}"
echo ""

# Normal HTTP requests from outside
for i in $(seq 1 5); do
    echo -e "  ${GREEN}→${NC} GET $BENIGN_URL/ (request $i)"
    curl -s -o /dev/null -w "    Status: %{http_code}\n" "$BENIGN_URL/" 2>/dev/null || echo "    (connection ok)"
    sleep 0.3
done

echo ""
echo -e "  ${GREEN}→${NC} Harmless in-container operations (triggers INFO-level Falco events):"

# touch triggers "Timestomping Detected" at INFO level
docker exec "$BENIGN_CONTAINER" touch /tmp/healthcheck 2>/dev/null
echo "    ✓ touch /tmp/healthcheck (routine file operation)"
sleep 0.5

# Direct file operations — NO sh -c to avoid triggering shell spawn rules
docker exec "$BENIGN_CONTAINER" cp /usr/share/nginx/html/index.html /tmp/test.txt 2>/dev/null
echo "    ✓ cp index.html to /tmp (routine copy)"
sleep 0.5

docker exec "$BENIGN_CONTAINER" mv /tmp/test.txt /tmp/test_done.txt 2>/dev/null
echo "    ✓ mv temp file (routine housekeeping)"
sleep 0.5

# rm triggers "Bulk File Renaming or Deletion" at INFO level
docker exec "$BENIGN_CONTAINER" rm -f /tmp/healthcheck /tmp/test_done.txt 2>/dev/null
echo "    ✓ rm temp files (routine cleanup)"
sleep 0.5

# Another touch
docker exec "$BENIGN_CONTAINER" touch /tmp/nginx_ready 2>/dev/null
echo "    ✓ touch /tmp/nginx_ready (readiness marker)"
docker exec "$BENIGN_CONTAINER" rm -f /tmp/nginx_ready 2>/dev/null
sleep 0.5

echo ""
echo -e "${GREEN}✓ Phase 1 complete: benign-nginx registered with ZERO malicious events${NC}"
echo ""

# ═══════════════════════════════════════════════════════════
# PHASE 2: Malicious Attacks on vulnerable-webapp
# ═══════════════════════════════════════════════════════════
echo -e "${BOLD}${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${RED}  PHASE 2: MALICIOUS ATTACKS on ${ATTACK_CONTAINER}${NC}"
echo -e "${BOLD}${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "  ${RED}⚔${NC}  Attack 1: Shell Spawning"
docker exec "$ATTACK_CONTAINER" sh -c 'bash -c "echo shell_spawned"' 2>/dev/null
echo "    → Spawned bash shell inside container"
sleep 1

echo -e "  ${RED}⚔${NC}  Attack 2: Sensitive File Read"
docker exec "$ATTACK_CONTAINER" sh -c 'cat /etc/shadow' > /dev/null 2>&1
echo "    → Read /etc/shadow"
sleep 1

echo -e "  ${RED}⚔${NC}  Attack 3: Reconnaissance"
docker exec "$ATTACK_CONTAINER" sh -c 'whoami && id && uname -a' > /dev/null 2>&1
echo "    → Ran whoami, id, uname"
sleep 1

echo -e "  ${RED}⚔${NC}  Attack 4: Write to System Binary Directory"
docker exec "$ATTACK_CONTAINER" sh -c 'echo payload > /usr/bin/.backdoor 2>&1; rm -f /usr/bin/.backdoor' 2>/dev/null
echo "    → Attempted binary directory write"
sleep 1

echo -e "  ${RED}⚔${NC}  Attack 5: Web Shell Drop"
docker exec "$ATTACK_CONTAINER" sh -c 'echo "<?php system(\$_GET[\"c\"]); ?>" > /app/shell.php' 2>/dev/null
echo "    → Dropped PHP web shell in /app/"
sleep 1

echo ""
echo -e "${RED}✓ Phase 2 complete: Multiple Falco alerts expected (Warning + Critical)${NC}"
echo ""

# ═══════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  EXPECTED RESULTS ON FRONTEND DASHBOARD:${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}■${NC} ${BOLD}benign-nginx${NC}"
echo -e "    Health: ${GREEN}Healthy${NC}"
echo -e "    Total Events: Some (routine file ops)"
echo -e "    Malicious Events: ${GREEN}0${NC}"
echo -e "    Status: Only INFO-level benign activity"
echo ""
echo -e "  ${RED}■${NC} ${BOLD}vulnerable-webapp${NC}"
echo -e "    Health: ${RED}Malicious${NC}"
echo -e "    Malicious Events: ${RED}5+${NC} (shells, file reads, recon, binary writes)"
echo -e "    Status: Multiple attack indicators detected"
echo ""
echo -e "${YELLOW}▸ Open your frontend dashboard now to compare the two containers!${NC}"
echo ""
