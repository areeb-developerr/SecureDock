#!/bin/bash
#
# Interactive Single Attack Tester for Secure Dock
# Pick a container and an attack type to test one at a time
#

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

run_in_container() {
    local container="$1"
    local command="$2"
    local desc="$3"
    echo -e "  ${CYAN}→${NC} $desc"
    echo -e "    ${BOLD}Command:${NC} $command"
    output=$(docker exec "$container" sh -c "$command" 2>&1) && status=0 || status=1
    if [ $status -eq 0 ]; then
        echo -e "    ${GREEN}✓ Success${NC}: $(echo "$output" | head -1)"
    else
        echo -e "    ${YELLOW}! Result${NC}: $(echo "$output" | head -1)"
    fi
    sleep 0.5
}

# ── Attack Functions ───────────────────────────────────────────

attack_shell_spawn() {
    local c="$1"
    echo -e "\n${RED}${BOLD}⚔  ATTACK: Shell Spawning${NC}"
    echo -e "${YELLOW}Falco Rule: Shell Spawned in Container${NC}"
    echo ""
    run_in_container "$c" "bash -c 'echo shell_spawned'" "Spawning bash shell"
    run_in_container "$c" "sh -c 'echo shell_spawned'" "Spawning sh shell"
    run_in_container "$c" "dash -c 'echo shell_spawned' 2>/dev/null || sh -c 'echo fallback'" "Spawning dash shell"
    echo -e "\n${GREEN}▸ Expected on Frontend:${NC} 'Shell Spawned in Container' events (Warning)"
}

attack_sensitive_file_read() {
    local c="$1"
    echo -e "\n${RED}${BOLD}⚔  ATTACK: Sensitive File Read${NC}"
    echo -e "${YELLOW}Falco Rule: Sensitive File Read / Read sensitive file untrusted${NC}"
    echo ""
    run_in_container "$c" "cat /etc/shadow" "Reading /etc/shadow"
    run_in_container "$c" "cat /etc/sudoers 2>/dev/null || echo 'not found'" "Reading /etc/sudoers"
    run_in_container "$c" "cat /root/.ssh/id_rsa 2>/dev/null || echo 'not found'" "Reading SSH private key"
    echo -e "\n${GREEN}▸ Expected on Frontend:${NC} 'Sensitive File Read' and/or 'Read sensitive file untrusted' events (Warning)"
}

attack_recon_tools() {
    local c="$1"
    echo -e "\n${RED}${BOLD}⚔  ATTACK: Reconnaissance${NC}"
    echo -e "${YELLOW}Falco Rule: Reconnaissance Tool Execution${NC}"
    echo ""
    run_in_container "$c" "whoami" "Running whoami"
    run_in_container "$c" "id" "Running id"
    run_in_container "$c" "uname -a" "Running uname"
    run_in_container "$c" "hostname" "Running hostname"
    run_in_container "$c" "ps aux 2>/dev/null | head -5" "Running ps aux"
    echo -e "\n${GREEN}▸ Expected on Frontend:${NC} 'Reconnaissance Tool Execution' events (Notice)"
}

attack_write_binary_dir() {
    local c="$1"
    echo -e "\n${RED}${BOLD}⚔  ATTACK: Write to System Binary Directory${NC}"
    echo -e "${YELLOW}Falco Rule: System Binary Modification${NC}"
    echo ""
    run_in_container "$c" "echo 'payload' > /usr/bin/.backdoor 2>&1; rm -f /usr/bin/.backdoor 2>&1" "Writing to /usr/bin/"
    run_in_container "$c" "echo 'payload' > /bin/.backdoor 2>&1; rm -f /bin/.backdoor 2>&1" "Writing to /bin/"
    echo -e "\n${GREEN}▸ Expected on Frontend:${NC} 'System Binary Modification' events (Critical)"
}

attack_privilege_escalation() {
    local c="$1"
    echo -e "\n${RED}${BOLD}⚔  ATTACK: Privilege Escalation${NC}"
    echo -e "${YELLOW}Falco Rule: PrivEsc Tool Executed${NC}"
    echo ""
    run_in_container "$c" "sudo -l 2>&1 || echo 'sudo not available'" "Attempting sudo"
    run_in_container "$c" "su -c 'whoami' root 2>&1 || echo 'su failed'" "Attempting su"
    run_in_container "$c" "chmod +s /bin/sh 2>&1 || echo 'chmod failed'" "Setting SUID on shell"
    echo -e "\n${GREEN}▸ Expected on Frontend:${NC} 'PrivEsc Tool Executed' events (Notice)"
}

attack_webroot_write() {
    local c="$1"
    echo -e "\n${RED}${BOLD}⚔  ATTACK: Web Shell Upload${NC}"
    echo -e "${YELLOW}Falco Rule: Script Written to Webroot${NC}"
    echo ""
    run_in_container "$c" "echo '<?php system(\$_GET[\"cmd\"]); ?>' > /app/shell.php 2>&1 || echo 'write failed'" "Dropping PHP web shell in /app/"
    run_in_container "$c" "echo 'import os; os.system(\"ls\")' > /var/www/exploit.py 2>&1 || echo 'write failed'" "Dropping Python script in /var/www/"
    echo -e "\n${GREEN}▸ Expected on Frontend:${NC} 'Script Written to Webroot' events (Warning)"
}

attack_container_escape() {
    local c="$1"
    echo -e "\n${RED}${BOLD}⚔  ATTACK: Container Escape Attempt${NC}"
    echo -e "${YELLOW}Falco Rule: Privileged Component Execution / Kernel Debug Access${NC}"
    echo ""
    run_in_container "$c" "mount 2>&1 | head -3" "Running mount"
    run_in_container "$c" "nsenter --target 1 --mount ls / 2>&1 || echo 'nsenter not available'" "Attempting nsenter escape"
    run_in_container "$c" "cat /proc/sched_debug 2>/dev/null | head -3 || echo 'not accessible'" "Reading kernel debug info"
    echo -e "\n${GREEN}▸ Expected on Frontend:${NC} 'Container Management Tool' / 'Kernel Debug' events (Warning)"
}

attack_log_tampering() {
    local c="$1"
    echo -e "\n${RED}${BOLD}⚔  ATTACK: Log Tampering${NC}"
    echo -e "${YELLOW}Falco Rule: Log File Tampering${NC}"
    echo ""
    run_in_container "$c" "echo 'tampered' >> /var/log/auth.log 2>&1 || echo 'not writable'" "Appending to auth.log"
    run_in_container "$c" "rm -f /var/log/syslog 2>&1 || echo 'not deletable'" "Attempting to delete syslog"
    echo -e "\n${GREEN}▸ Expected on Frontend:${NC} 'Log File Tampering' events (Warning)"
}

# ── Main Menu ──────────────────────────────────────────────────

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       SECURE DOCK — Single Attack Tester          ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Pick a container
echo -e "${BOLD}Running containers:${NC}"
echo ""
mapfile -t CONTAINERS < <(docker ps --format '{{.Names}}' | grep -v falco-monitor | sort)

if [ ${#CONTAINERS[@]} -eq 0 ]; then
    echo -e "${RED}No running containers found! Start your containers first.${NC}"
    exit 1
fi

for i in "${!CONTAINERS[@]}"; do
    echo -e "  ${CYAN}$((i+1)))${NC} ${CONTAINERS[$i]}"
done

echo ""
read -p "Select target container [1-${#CONTAINERS[@]}]: " choice
CONTAINER="${CONTAINERS[$((choice-1))]}"

if [ -z "$CONTAINER" ]; then
    echo -e "${RED}Invalid selection.${NC}"
    exit 1
fi

echo -e "\n${GREEN}Target: ${BOLD}$CONTAINER${NC}\n"

# Step 2: Pick an attack
while true; do
    echo -e "${BOLD}Available attacks:${NC}"
    echo ""
    echo -e "  ${CYAN}1)${NC} Shell Spawning         — Triggers 'Shell Spawned in Container'"
    echo -e "  ${CYAN}2)${NC} Sensitive File Read     — Triggers 'Sensitive File Read'"
    echo -e "  ${CYAN}3)${NC} Reconnaissance Tools    — Triggers 'Reconnaissance Tool Execution'"
    echo -e "  ${CYAN}4)${NC} Write to Binary Dir     — Triggers 'System Binary Modification'"
    echo -e "  ${CYAN}5)${NC} Privilege Escalation    — Triggers 'PrivEsc Tool Executed'"
    echo -e "  ${CYAN}6)${NC} Web Shell Upload        — Triggers 'Script Written to Webroot'"
    echo -e "  ${CYAN}7)${NC} Container Escape        — Triggers 'Container Management Tool'"
    echo -e "  ${CYAN}8)${NC} Log Tampering           — Triggers 'Log File Tampering'"
    echo -e "  ${CYAN}a)${NC} Run ALL attacks above"
    echo -e "  ${CYAN}q)${NC} Quit"
    echo ""
    read -p "Select attack [1-8/a/q]: " attack_choice

    case "$attack_choice" in
        1) attack_shell_spawn "$CONTAINER" ;;
        2) attack_sensitive_file_read "$CONTAINER" ;;
        3) attack_recon_tools "$CONTAINER" ;;
        4) attack_write_binary_dir "$CONTAINER" ;;
        5) attack_privilege_escalation "$CONTAINER" ;;
        6) attack_webroot_write "$CONTAINER" ;;
        7) attack_container_escape "$CONTAINER" ;;
        8) attack_log_tampering "$CONTAINER" ;;
        a|A)
            attack_shell_spawn "$CONTAINER"
            sleep 1
            attack_sensitive_file_read "$CONTAINER"
            sleep 1
            attack_recon_tools "$CONTAINER"
            sleep 1
            attack_write_binary_dir "$CONTAINER"
            sleep 1
            attack_privilege_escalation "$CONTAINER"
            sleep 1
            attack_webroot_write "$CONTAINER"
            sleep 1
            attack_container_escape "$CONTAINER"
            sleep 1
            attack_log_tampering "$CONTAINER"
            ;;
        q|Q)
            echo -e "\n${GREEN}Done! Check your frontend dashboard for detected events.${NC}\n"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Try again.${NC}"
            ;;
    esac

    echo ""
    echo -e "${YELLOW}─────────────────────────────────────────${NC}"
    echo -e "${GREEN}Check your frontend now to see the detection!${NC}"
    echo -e "${YELLOW}─────────────────────────────────────────${NC}"
    echo ""
done
