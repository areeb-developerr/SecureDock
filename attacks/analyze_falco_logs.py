#!/usr/bin/env python3
"""
Falco Log Analysis Script
Analyzes Falco logs to identify malicious activity
"""

import json
import sys
import os
from pathlib import Path

def analyze_falco_logs(log_file_path):
    """Analyze Falco logs and categorize alerts"""
    project_root = Path(__file__).parent.parent
    log_path = project_root / "falco-logs" / "output.log"
    
    if not log_path.exists():
        print(f"[!] Falco log file not found at: {log_path}")
        print("[!] Make sure Falco is running and logging to the correct location.")
        return False
    
    print("\n" + "="*60)
    print("FALCO LOG ANALYSIS")
    print("="*60)
    print(f"\nAnalyzing log file: {log_path}")
    print()
    
    alerts = []
    benign_count = 0
    malicious_count = 0
    
    try:
        with open(log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Try to parse as JSON (Falco JSON output)
                    alert = json.loads(line)
                    alerts.append(alert)
                    
                    # Check priority/severity
                    priority = alert.get('priority', '').lower()
                    rule = alert.get('rule', '')
                    output = alert.get('output', '')
                    
                    if priority in ['warning', 'error', 'critical']:
                        malicious_count += 1
                        print(f"[!] MALICIOUS ACTIVITY DETECTED (Line {line_num})")
                        print(f"    Priority: {priority.upper()}")
                        print(f"    Rule: {rule}")
                        print(f"    Output: {output[:200]}")
                        print()
                    else:
                        benign_count += 1
                        
                except json.JSONDecodeError:
                    # Not JSON, try to parse as text log
                    if any(keyword in line.lower() for keyword in ['warning', 'error', 'alert', 'suspicious']):
                        malicious_count += 1
                        print(f"[!] POTENTIAL ALERT (Line {line_num}): {line[:200]}")
                    else:
                        benign_count += 1
    
    except FileNotFoundError:
        print(f"[!] Log file not found: {log_path}")
        return False
    except Exception as e:
        print(f"[!] Error reading log file: {e}")
        return False
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Total log entries analyzed: {len(alerts) if alerts else 'N/A'}")
    print(f"Benign entries: {benign_count}")
    print(f"Malicious/Alert entries: {malicious_count}")
    print()
    
    if malicious_count > 0:
        print("[!] Falco detected malicious activity!")
        print("[!] Review the alerts above for details.")
    else:
        print("[+] No malicious activity detected in Falco logs.")
        print("[*] This could mean:")
        print("    - All activity was benign")
        print("    - Falco rules need tuning")
        print("    - Attacks didn't trigger Falco rules")
    
    return True

if __name__ == "__main__":
    analyze_falco_logs(None)

