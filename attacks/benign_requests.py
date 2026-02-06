#!/usr/bin/env python3
"""
Benign Requests Script
Sends normal, legitimate requests to the webapp
"""

import requests
import time
import sys

BASE_URL = "http://localhost:5000"

def benign_requests():
    """Send benign/normal requests to the webapp"""
    print("\n" + "="*60)
    print("BENIGN REQUESTS - Normal Usage Simulation")
    print("="*60)
    
    try:
        # Home page
        print("\n[*] Accessing home page...")
        response = requests.get(f"{BASE_URL}/", timeout=5)
        print(f"[+] Status: {response.status_code}")
        time.sleep(1)
        
        # List items
        print("\n[*] Listing items...")
        response = requests.get(f"{BASE_URL}/items", timeout=5)
        print(f"[+] Status: {response.status_code}")
        time.sleep(1)
        
        # View specific item
        print("\n[*] Viewing item details...")
        response = requests.get(f"{BASE_URL}/item/1", timeout=5)
        print(f"[+] Status: {response.status_code}")
        time.sleep(1)
        
        # Normal search
        print("\n[*] Performing normal search...")
        response = requests.get(f"{BASE_URL}/search", params={'q': 'laptop'}, timeout=5)
        print(f"[+] Status: {response.status_code}")
        time.sleep(1)
        
        # Add item form (GET)
        print("\n[*] Accessing add item form...")
        response = requests.get(f"{BASE_URL}/add", timeout=5)
        print(f"[+] Status: {response.status_code}")
        time.sleep(1)
        
        # Add a legitimate item
        print("\n[*] Adding legitimate item...")
        response = requests.post(
            f"{BASE_URL}/add",
            data={
                'name': 'Monitor',
                'description': '27 inch monitor',
                'price': '199.99'
            },
            timeout=5
        )
        print(f"[+] Status: {response.status_code}")
        time.sleep(1)
        
        # Login with correct credentials
        print("\n[*] Logging in with correct credentials...")
        response = requests.post(
            f"{BASE_URL}/login",
            data={
                'username': 'admin',
                'password': 'admin123'
            },
            allow_redirects=False,
            timeout=5
        )
        print(f"[+] Status: {response.status_code}")
        time.sleep(1)
        
        print("\n[+] Benign requests completed successfully")
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")
        return False

if __name__ == "__main__":
    print("Starting Benign Requests...")
    print("Make sure the webapp is running on http://localhost:5000")
    time.sleep(2)
    
    success = benign_requests()
    sys.exit(0 if success else 1)

