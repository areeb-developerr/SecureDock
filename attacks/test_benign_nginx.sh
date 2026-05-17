#!/bin/bash
#
# Benign Activity Generator for benign-nginx
# Simulates normal, safe container operations that produce
# only INFO-level Falco events (no malicious indicators)
#

GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CONTAINER="benign-nginx"
URL="http://localhost:8888"

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     Benign Activity Generator — benign-nginx          ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check container
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo -e "\033[0;31m✗ Container '$CONTAINER' is not running!\033[0m"
    echo "  Run: cd docker && docker compose up -d"
    exit 1
fi
echo -e "${GREEN}✓ Container ${CONTAINER} is running${NC}"
echo ""

# ── Phase 1: External HTTP requests (no Falco events) ──
echo -e "${BOLD}Phase 1: Normal HTTP Traffic${NC}"
echo -e "${CYAN}(External requests — no Falco events generated)${NC}"
echo ""

for i in $(seq 1 8); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$URL/" 2>/dev/null)
    echo -e "  ${GREEN}→${NC} GET $URL/ — Status: $code"
    sleep 0.3
done

code=$(curl -s -o /dev/null -w "%{http_code}" "$URL/index.html" 2>/dev/null)
echo -e "  ${GREEN}→${NC} GET $URL/index.html — Status: $code"

code=$(curl -s -o /dev/null -w "%{http_code}" "$URL/50x.html" 2>/dev/null)
echo -e "  ${GREEN}→${NC} GET $URL/50x.html — Status: $code"

echo ""

# ── Phase 2: Harmless in-container operations (INFO events) ──
echo -e "${BOLD}Phase 2: Routine Container Operations${NC}"
echo -e "${CYAN}(Triggers INFO-level Falco events only — all benign)${NC}"
echo ""

# File creation
docker exec "$CONTAINER" touch /tmp/healthcheck 2>/dev/null
echo -e "  ${GREEN}✓${NC} touch /tmp/healthcheck"
sleep 0.3

# File copy
docker exec "$CONTAINER" cp /usr/share/nginx/html/index.html /tmp/index_backup.html 2>/dev/null
echo -e "  ${GREEN}✓${NC} cp index.html → /tmp/index_backup.html"
sleep 0.3

# File rename
docker exec "$CONTAINER" mv /tmp/index_backup.html /tmp/index_old.html 2>/dev/null
echo -e "  ${GREEN}✓${NC} mv index_backup.html → index_old.html"
sleep 0.3

# File cleanup
docker exec "$CONTAINER" rm -f /tmp/healthcheck /tmp/index_old.html 2>/dev/null
echo -e "  ${GREEN}✓${NC} rm temp files"
sleep 0.3

# Another round of routine housekeeping
docker exec "$CONTAINER" touch /tmp/ready_marker 2>/dev/null
echo -e "  ${GREEN}✓${NC} touch /tmp/ready_marker"
sleep 0.3

docker exec "$CONTAINER" cp /etc/nginx/nginx.conf /tmp/nginx_conf_check 2>/dev/null
echo -e "  ${GREEN}✓${NC} cp nginx.conf → /tmp (config review)"
sleep 0.3

docker exec "$CONTAINER" rm -f /tmp/ready_marker /tmp/nginx_conf_check 2>/dev/null
echo -e "  ${GREEN}✓${NC} rm temp files"
sleep 0.3

# Check nginx process (direct, no shell wrapper)
docker exec "$CONTAINER" cat /proc/1/status > /dev/null 2>&1
echo -e "  ${GREEN}✓${NC} cat /proc/1/status (process health check)"

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ All benign activities completed${NC}"
echo -e "  Total HTTP requests: 10"
echo -e "  Total in-container ops: 8"
echo -e "  Expected malicious events: ${BOLD}0${NC}"
echo -e ""
echo -e "  ${CYAN}▸ Check your frontend — benign-nginx should show as Healthy${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
