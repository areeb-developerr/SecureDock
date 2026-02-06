#!/usr/bin/env python3
"""
Falco-Detectable Attack Script
Performs attacks that WILL trigger Falco detection rules
These are system-level activities that generate detectable system calls
"""

import subprocess
import time
import sys
import os

def run_in_container(container_name, command, description):
    """Run a command in a container and report results"""
    print(f"\n[*] {description}")
    print(f"    Command: {command}")
    try:
        result = subprocess.run(
            ['docker', 'exec', container_name, 'sh', '-c', command],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print(f"    [+] Success - Output: {result.stdout[:100]}")
        else:
            print(f"    [!] Error: {result.stderr[:100]}")
        return result.returncode == 0
    except Exception as e:
        print(f"    [!] Exception: {e}")
        return False

def attack_shell_spawning(container):
    """Attack 1: Spawn shells - Falco detects shell spawning"""
    print("\n" + "="*60)
    print("ATTACK 1: SHELL SPAWNING (Falco Rule: shell_spawned)")
    print("="*60)
    
    shells = ['/bin/sh', '/bin/bash', '/bin/ash', '/bin/dash']
    
    for shell in shells:
        run_in_container(
            container,
            f"{shell} -c 'echo Shell spawned from {shell}'",
            f"Spawning {shell}"
        )
        time.sleep(1)
    
    # Spawn interactive shell (simulated)
    run_in_container(
        container,
        "/bin/sh -c 'export PS1=\"# \"; echo Interactive shell'",
        "Spawning interactive shell"
    )
    
    return True

def attack_sensitive_file_access(container):
    """Attack 2: Read sensitive files - Falco detects sensitive file reads"""
    print("\n" + "="*60)
    print("ATTACK 2: SENSITIVE FILE ACCESS (Falco Rule: read_sensitive_file)")
    print("="*60)
    
    sensitive_files = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/etc/group',
        '/proc/version',
        '/proc/cmdline',
        '/proc/mounts',
        '/root/.ssh/id_rsa',
        '/root/.bash_history',
    ]
    
    for file_path in sensitive_files:
        run_in_container(
            container,
            f"cat {file_path} 2>/dev/null | head -3",
            f"Reading sensitive file: {file_path}"
        )
        time.sleep(0.5)
    
    # Attempt to read multiple sensitive files in sequence
    run_in_container(
        container,
        "cat /etc/passwd /etc/shadow /etc/group 2>/dev/null | head -5",
        "Reading multiple sensitive files"
    )
    
    return True

def attack_write_sensitive_directories(container):
    """Attack 3: Write to sensitive directories - Falco detects writes to system dirs"""
    print("\n" + "="*60)
    print("ATTACK 3: WRITE TO SENSITIVE DIRECTORIES (Falco Rule: write_below_binary_dir)")
    print("="*60)
    
    sensitive_dirs = [
        '/bin',
        '/sbin',
        '/usr/bin',
        '/usr/sbin',
        '/etc',
        '/root',
    ]
    
    for directory in sensitive_dirs:
        run_in_container(
            container,
            f"echo 'malicious_code' > {directory}/.test_file 2>&1; rm -f {directory}/.test_file 2>&1",
            f"Attempting to write to: {directory}"
        )
        time.sleep(0.5)
    
    return True

def attack_privilege_escalation(container):
    """Attack 4: Privilege escalation attempts - Falco detects privilege changes"""
    print("\n" + "="*60)
    print("ATTACK 4: PRIVILEGE ESCALATION (Falco Rule: setuid_setgid)")
    print("="*60)
    
    # Attempt sudo
    run_in_container(
        container,
        "sudo -l 2>&1 || echo 'sudo not available'",
        "Attempting sudo privilege check"
    )
    
    # Attempt su
    run_in_container(
        container,
        "su -c 'whoami' root 2>&1 || echo 'su failed'",
        "Attempting su to root"
    )
    
    # Check current privileges
    run_in_container(
        container,
        "id && whoami",
        "Checking current user privileges"
    )
    
    # Attempt to change user ID (if possible)
    run_in_container(
        container,
        "chmod +s /bin/sh 2>&1 || echo 'chmod failed'",
        "Attempting to set SUID on shell"
    )
    
    return True

def attack_container_escape(container):
    """Attack 5: Container escape attempts - Falco detects namespace access"""
    print("\n" + "="*60)
    print("ATTACK 5: CONTAINER ESCAPE (Falco Rule: container_escape)")
    print("="*60)
    
    # Attempt to access host filesystem
    run_in_container(
        container,
        "ls -la /host 2>&1 || ls -la / 2>&1 | head -10",
        "Attempting to access host filesystem"
    )
    
    # Attempt to access host proc
    run_in_container(
        container,
        "cat /proc/1/cmdline 2>&1 | head -1",
        "Attempting to read host process info"
    )
    
    # Attempt to mount host filesystem
    run_in_container(
        container,
        "mount -t proc proc /tmp/proc 2>&1 || echo 'mount failed'",
        "Attempting to mount host filesystem"
    )
    
    # Attempt nsenter (if available)
    run_in_container(
        container,
        "nsenter --target 1 --mount ls / 2>&1 || echo 'nsenter not available'",
        "Attempting namespace escape with nsenter"
    )
    
    return True

def attack_unexpected_network(container):
    """Attack 6: Unexpected network connections - Falco detects outbound connections"""
    print("\n" + "="*60)
    print("ATTACK 6: UNEXPECTED NETWORK CONNECTIONS (Falco Rule: outbound_connection)")
    print("="*60)
    
    # Attempt outbound connections
    test_hosts = [
        '8.8.8.8',
        '1.1.1.1',
        'google.com',
        'malicious.example.com',
    ]
    
    for host in test_hosts:
        run_in_container(
            container,
            f"nc -zv {host} 80 2>&1 || curl -s --connect-timeout 2 http://{host} 2>&1 | head -1 || echo 'Connection failed'",
            f"Attempting outbound connection to: {host}"
        )
        time.sleep(1)
    
    # Attempt DNS queries
    run_in_container(
        container,
        "nslookup google.com 2>&1 || host google.com 2>&1 || echo 'DNS tools not available'",
        "Performing DNS queries"
    )
    
    return True

def attack_process_anomalies(container):
    """Attack 7: Process anomalies - Falco detects unusual process execution"""
    print("\n" + "="*60)
    print("ATTACK 7: PROCESS ANOMALIES (Falco Rule: suspicious_process)")
    print("="*60)
    
    # Spawn multiple processes rapidly
    run_in_container(
        container,
        "for i in $(seq 1 10); do sh -c 'echo Process $i' & done; wait",
        "Spawning multiple processes rapidly"
    )
    
    # Execute suspicious binaries
    suspicious_commands = [
        'wget',
        'curl',
        'nc',
        'netcat',
        'python -c "import os; os.system(\"ls\")"',
    ]
    
    for cmd in suspicious_commands:
        run_in_container(
            container,
            f"which {cmd.split()[0]} 2>&1 || echo '{cmd.split()[0]} not found'",
            f"Checking for suspicious tool: {cmd.split()[0]}"
        )
    
    # Attempt to hide process
    run_in_container(
        container,
        "sh -c '(sleep 1 &)' && ps aux | grep sleep",
        "Attempting to hide process"
    )
    
    return True

def attack_crypto_mining(container):
    """Attack 8: Cryptocurrency mining - Falco detects mining software"""
    print("\n" + "="*60)
    print("ATTACK 8: CRYPTO MINING DETECTION (Falco Rule: crypto_miners)")
    print("="*60)
    
    # Simulate mining activity (CPU intensive)
    run_in_container(
        container,
        "timeout 2 sh -c 'while true; do echo mining; done' 2>&1 | head -5 || echo 'Mining simulation'",
        "Simulating crypto mining activity"
    )
    
    # Check for mining-related processes
    mining_keywords = ['minerd', 'xmrig', 'cpuminer', 'ccminer']
    for keyword in mining_keywords:
        run_in_container(
            container,
            f"ps aux | grep -i {keyword} 2>&1 || echo '{keyword} not found'",
            f"Checking for mining process: {keyword}"
        )
    
    return True

def attack_file_system_anomalies(container):
    """Attack 9: File system anomalies - Falco detects unusual file operations"""
    print("\n" + "="*60)
    print("ATTACK 9: FILE SYSTEM ANOMALIES (Falco Rule: file_anomaly)")
    print("="*60)
    
    # Create files in unusual locations
    run_in_container(
        container,
        "touch /tmp/.hidden_file && chmod 777 /tmp/.hidden_file && ls -la /tmp/.hidden_file",
        "Creating hidden file"
    )
    
    # Modify system files
    run_in_container(
        container,
        "echo 'test' >> /etc/hosts 2>&1 || echo 'Cannot modify /etc/hosts'",
        "Attempting to modify system file"
    )
    
    # Search for sensitive files
    run_in_container(
        container,
        "find / -name '*.key' -o -name '*.pem' -o -name 'id_rsa' 2>/dev/null | head -5",
        "Searching for sensitive key files"
    )
    
    return True

def main():
    """Main attack function"""
    print("="*60)
    print("FALCO-DETECTABLE ATTACK SUITE")
    print("="*60)
    print("\nThis script performs attacks that WILL trigger Falco detection rules.")
    print("All attacks are system-level activities that generate detectable system calls.\n")
    
    # Get container name
    containers = ['dvwa-container', 'juice-shop-container']
    
    for container in containers:
        # Check if container exists
        try:
            result = subprocess.run(
                ['docker', 'ps', '--filter', f'name={container}', '--format', '{{.Names}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if container not in result.stdout:
                print(f"[!] Container {container} not running, skipping...")
                continue
        except:
            continue
        
        print(f"\n{'='*60}")
        print(f"ATTACKING CONTAINER: {container}")
        print(f"{'='*60}")
        
        # Perform all attacks
        attack_shell_spawning(container)
        time.sleep(2)
        
        attack_sensitive_file_access(container)
        time.sleep(2)
        
        attack_write_sensitive_directories(container)
        time.sleep(2)
        
        attack_privilege_escalation(container)
        time.sleep(2)
        
        attack_container_escape(container)
        time.sleep(2)
        
        attack_unexpected_network(container)
        time.sleep(2)
        
        attack_process_anomalies(container)
        time.sleep(2)
        
        attack_crypto_mining(container)
        time.sleep(2)
        
        attack_file_system_anomalies(container)
        time.sleep(2)
    
    print("\n" + "="*60)
    print("ALL ATTACKS COMPLETED")
    print("="*60)
    print("\nCheck Falco logs for detections:")
    print("  tail -f falco-logs/output.log")
    print("  docker logs falco-monitor-vulnerable")
    print()
    
    return True

if __name__ == "__main__":
    main()

