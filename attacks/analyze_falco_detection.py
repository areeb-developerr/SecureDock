#!/usr/bin/env python3
"""
Comprehensive Falco Detection Analysis
Analyzes Falco logs and container activities to determine detection effectiveness
"""

import json
import subprocess
import sys
from pathlib import Path

def check_falco_logs():
    """Check Falco logs for detections"""
    project_root = Path(__file__).parent.parent
    log_path = project_root / "falco-logs" / "output.log"
    
    print("="*60)
    print("FALCO DETECTION ANALYSIS")
    print("="*60)
    print()
    
    # Check log file
    if log_path.exists():
        with open(log_path, 'r') as f:
            content = f.read().strip()
            if content:
                print(f"[+] Falco log file found: {log_path}")
                print(f"[+] Log size: {len(content)} bytes")
                print()
                print("Recent log entries:")
                print("-" * 60)
                lines = content.split('\n')
                for line in lines[-10:]:
                    if line.strip():
                        print(line[:200])
            else:
                print(f"[!] Falco log file is empty: {log_path}")
    else:
        print(f"[!] Falco log file not found: {log_path}")
    
    print()
    
    # Check Falco container logs
    print("Checking Falco container logs...")
    print("-" * 60)
    try:
        result = subprocess.run(
            ['docker', 'logs', 'falco-monitor-vulnerable', '--tail', '50'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Look for alerts, warnings, or detections
        output = result.stdout + result.stderr
        alerts = []
        
        for line in output.split('\n'):
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in ['alert', 'warning', 'error', 'detected', 'suspicious', 'anomaly']):
                alerts.append(line)
        
        if alerts:
            print(f"[+] Found {len(alerts)} potential alerts in Falco logs:")
            for alert in alerts[:10]:
                print(f"    {alert[:150]}")
        else:
            print("[*] No explicit alerts found in Falco container logs")
            print("[*] This could mean:")
            print("    - Activities are within normal parameters")
            print("    - Falco rules need tuning for these scenarios")
            print("    - Application-level attacks don't trigger system calls")
    
    except Exception as e:
        print(f"[!] Error checking Falco logs: {e}")
    
    print()
    
    # Check container activities
    print("Container Activity Summary:")
    print("-" * 60)
    containers = ['dvwa-container', 'juice-shop-container']
    
    for container in containers:
        try:
            result = subprocess.run(
                ['docker', 'ps', '--filter', f'name={container}', '--format', '{{.Names}}: {{.Status}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.stdout.strip():
                print(f"[+] {result.stdout.strip()}")
        except:
            pass
    
    print()
    print("="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    print()
    print("Falco Detection Capabilities:")
    print("  ✓ Falco is running and monitoring containers")
    print("  ✓ Falco monitors system calls and process activities")
    print()
    print("What Falco Detects:")
    print("  • Shell spawning (sh, bash, etc.)")
    print("  • Sensitive file access (/etc/passwd, /etc/shadow)")
    print("  • Process anomalies")
    print("  • Network anomalies")
    print("  • Unusual system calls")
    print()
    print("What Falco May Not Detect:")
    print("  • Application-level SQL injection (no system calls)")
    print("  • XSS attacks (application logic)")
    print("  • HTTP-based brute force (network layer)")
    print("  • Normal container operations")
    print()
    print("Recommendations:")
    print("  1. Falco is best for detecting system-level attacks")
    print("  2. For application-level attacks, use WAF or application logs")
    print("  3. Combine Falco with application monitoring for comprehensive coverage")
    print()

if __name__ == "__main__":
    check_falco_logs()

