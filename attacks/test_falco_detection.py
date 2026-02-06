#!/usr/bin/env python3
"""
Test script to trigger Falco detections
Performs activities that should definitely trigger Falco rules
"""

import subprocess
import time
import sys

def run_command_in_container(container_name, command):
    """Run a command in a container"""
    try:
        result = subprocess.run(
            ['docker', 'exec', container_name, 'sh', '-c', command],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return "", str(e), -1

def test_falco_detections():
    """Perform various activities that should trigger Falco"""
    print("="*60)
    print("FALCO DETECTION TEST")
    print("="*60)
    print("\nPerforming activities that should trigger Falco rules...\n")
    
    containers = ['dvwa-container', 'juice-shop-container']
    
    for container in containers:
        print(f"\n[*] Testing on {container}")
        print("-" * 60)
        
        # Test 1: Spawn shell
        print("[1] Spawning shell...")
        stdout, stderr, code = run_command_in_container(container, "/bin/sh -c 'echo shell_test'")
        time.sleep(1)
        
        # Test 2: Read sensitive files
        print("[2] Reading /etc/passwd...")
        stdout, stderr, code = run_command_in_container(container, "cat /etc/passwd")
        time.sleep(1)
        
        # Test 3: Execute system commands
        print("[3] Executing system commands...")
        stdout, stderr, code = run_command_in_container(container, "whoami && id && uname -a")
        time.sleep(1)
        
        # Test 4: List processes
        print("[4] Listing processes...")
        stdout, stderr, code = run_command_in_container(container, "ps aux")
        time.sleep(1)
        
        # Test 5: Network operations
        print("[5] Network operations...")
        stdout, stderr, code = run_command_in_container(container, "netstat -an 2>/dev/null || ss -an 2>/dev/null || echo 'netstat not available'")
        time.sleep(1)
        
        # Test 6: File system operations
        print("[6] File system operations...")
        stdout, stderr, code = run_command_in_container(container, "find /tmp -type f 2>/dev/null | head -5")
        time.sleep(1)
    
    print("\n" + "="*60)
    print("Tests completed. Check Falco logs for detections.")
    print("="*60)
    return True

if __name__ == "__main__":
    test_falco_detections()

