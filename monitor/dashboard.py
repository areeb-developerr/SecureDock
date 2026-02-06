#!/usr/bin/env python3
"""
Real-Time Security Dashboard
Shows current monitoring status and recent windows
"""

import sys
import time
import os
from pathlib import Path
from datetime import datetime
import json

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')

# Global variable to track dashboard session start time
_dashboard_session_start = None

def read_falco_log(log_file, last_lines=50, since_time=None):
    """Read last N lines from Falco log or stderr, optionally filtered by time"""
    try:
        # Try reading from log file first
        if Path(log_file).exists():
            with open(log_file, 'r') as f:
                lines = f.readlines()
                if lines and len(lines) > 0:
                    return lines[-last_lines:] if len(lines) > last_lines else lines
        
        # Fallback: Read from Falco container stderr (where Falco actually writes)
        import subprocess
        try:
            # Use --since flag if provided to only get alerts from current session
            cmd = ['docker', 'logs', 'falco-monitor-vulnerable', '--tail', str(last_lines)]
            if since_time:
                cmd.extend(['--since', since_time])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.stdout:
                # Filter for JSON lines (alerts) - be more lenient with parsing
                json_lines = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try to find JSON object in the line (may not be at start)
                    if '{' in line and ('priority' in line or 'rule' in line):
                        try:
                            # Try to extract JSON object
                            json_start = line.find('{')
                            if json_start >= 0:
                                json_str = line[json_start:]
                                # Find matching closing brace
                                brace_count = 0
                                json_end = -1
                                for i, char in enumerate(json_str):
                                    if char == '{':
                                        brace_count += 1
                                    elif char == '}':
                                        brace_count -= 1
                                        if brace_count == 0:
                                            json_end = i + 1
                                            break
                                
                                if json_end > 0:
                                    json_obj = json_str[:json_end]
                                    # Validate it's valid JSON
                                    try:
                                        data = json.loads(json_obj)
                                        if data.get('priority') or data.get('rule'):
                                            json_lines.append(json_obj)
                                    except:
                                        pass
                        except:
                            # Fallback: try the whole line if it starts with {
                            if line.startswith('{'):
                                try:
                                    json.loads(line)
                                    json_lines.append(line)
                                except:
                                    pass
                return json_lines
        except:
            pass
        
        return []
    except:
        return []

def analyze_recent_activity(log_lines):
    """Analyze recent log activity"""
    malicious_count = 0
    benign_count = 0
    recent_alerts = []
    
    for line in log_lines:
        try:
            data = json.loads(line.strip())
            priority = data.get('priority', '').lower()
            rule = data.get('rule', '')
            output = data.get('output', '')
            
            if priority in ['critical', 'error', 'warning']:
                malicious_count += 1
                recent_alerts.append({
                    'priority': priority.upper(),
                    'rule': rule,
                    'output': output[:100]
                })
            else:
                benign_count += 1
        except:
            pass
    
    return malicious_count, benign_count, recent_alerts[-5:]  # Last 5 alerts

def print_dashboard():
    """Print the dashboard"""
    global _dashboard_session_start
    
    clear_screen()
    
    log_file = Path(__file__).parent.parent / "secure-dock-logs" / "output.log"
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Initialize session start time on first call
    if _dashboard_session_start is None:
        _dashboard_session_start = datetime.now()
    
    print(f"{BOLD}{BLUE}{'='*70}{RESET}")
    print(f"{BOLD}{BLUE}  SECURE DOCK MONITORING DASHBOARD{RESET}")
    print(f"{BOLD}{BLUE}{'='*70}{RESET}")
    print(f"Time: {current_time}")
    print(f"Session Start: {_dashboard_session_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Log File: {log_file}")
    print()
    
    # Read and analyze logs - only from current session
    # Calculate time since session started (add 5s buffer for safety)
    session_duration = (datetime.now() - _dashboard_session_start).total_seconds()
    since_time = f"{int(session_duration) + 5}s" if session_duration > 0 else "5s"
    log_lines = read_falco_log(str(log_file), last_lines=100, since_time=since_time)
    malicious, benign, alerts = analyze_recent_activity(log_lines)
    
    # Status summary
    print(f"{BOLD}STATUS SUMMARY{RESET}")
    print(f"{'─'*70}")
    print(f"{RED}🔴 Malicious Events: {malicious}{RESET}")
    print(f"Total Events (last 50): {len(log_lines)}")
    print()
    
    # Recent alerts
    if alerts:
        print(f"{BOLD}{RED}RECENT ALERTS (Last 5):{RESET}")
        print(f"{'─'*70}")
        for i, alert in enumerate(alerts, 1):
            priority_color = RED if alert['priority'] in ['CRITICAL', 'ERROR'] else YELLOW
            print(f"{priority_color}[{i}] {alert['priority']}: {alert['rule']}{RESET}")
            print(f"    {alert['output'][:80]}...")
            print()
    else:
        print(f"{GREEN}✓ No recent alerts - All activity appears benign{RESET}")
        print()
    
    # Instructions
    print(f"{BOLD}INSTRUCTIONS:{RESET}")
    print(f"{'─'*70}")
    print("1. Deploy your web application container")
    print("2. Browse the application normally (benign activity)")
    print("3. Perform attacks (malicious activity)")
    print("4. Watch this dashboard for real-time detection")
    print()
    print(f"{YELLOW}Press Ctrl+C to exit dashboard{RESET}")
    print(f"{'='*70}")

def run_dashboard():
    """Run the dashboard in a loop"""
    global _dashboard_session_start
    
    # Reset session start time when dashboard starts
    _dashboard_session_start = datetime.now()
    
    try:
        while True:
            print_dashboard()
            time.sleep(2)  # Update every 2 seconds (dashboard refresh rate)
    except KeyboardInterrupt:
        print(f"\n{BOLD}Dashboard stopped.{RESET}\n")
        # Reset session start time on exit so next run starts fresh
        _dashboard_session_start = None
        sys.exit(0)

if __name__ == "__main__":
    run_dashboard()

