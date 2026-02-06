#!/usr/bin/env python3
"""
Real-Time Security Monitor (STDERR Version)
Monitors Falco stderr directly since Falco writes alerts there
"""

import json
import time
import subprocess
from datetime import datetime
from collections import deque

class RealTimeMonitorStderr:
    def __init__(self, container_name='falco-monitor-vulnerable', window_size=10):
        self.container_name = container_name
        self.window_size = window_size
        self.monitoring = False
        self.current_window_start = None
        self.window_events = []
        self.window_flags = []
        self.last_timestamp = None
        self.monitored_containers = set()
        
        # Malicious indicators
        self.malicious_patterns = {
            'shell_spawned': ['shell', 'sh', 'bash', 'execve', 'Drop and execute'],
            'sensitive_file': ['/etc/passwd', '/etc/shadow', 'sensitive file', 'Read sensitive'],
            'write_binary': ['write_below_binary', '/bin/', '/sbin/', '/usr/bin/'],
            'privilege': ['setuid', 'setgid', 'sudo', 'su'],
            'container_escape': ['nsenter', 'mount', 'proc/1'],
            'suspicious_process': ['minerd', 'xmrig', 'crypto'],
            'network_anomaly': ['outbound', 'unexpected_network'],
        }
        
    def start_monitoring(self):
        """Start monitoring in background"""
        self.monitoring = True
        self.current_window_start = datetime.now()
        print(f"[*] Real-time monitoring started (window size: {self.window_size}s)")
        print(f"[*] Monitoring Falco container: {self.container_name}")
        print(f"[*] Reading from stderr (where Falco writes alerts)")
        
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        print("[*] Monitoring stopped")
    
    def parse_falco_log_line(self, line):
        """Parse a Falco log line and extract relevant information"""
        try:
            if not line.strip() or not line.strip().startswith('{'):
                return None
            
            # Parse JSON
            data = json.loads(line.strip())
            
            # Extract key information
            output = data.get('output', '')
            priority = data.get('priority', '').lower()
            rule = data.get('rule', '')
            container_name = data.get('output_fields', {}).get('container.name', 'unknown')
            time_str = data.get('time', '')
            
            return {
                'output': output,
                'priority': priority,
                'rule': rule,
                'container': container_name,
                'time': time_str,
                'raw': data
            }
        except (json.JSONDecodeError, KeyError, AttributeError):
            return None
    
    def is_malicious_event(self, event):
        """Determine if an event is malicious"""
        if not event:
            return False
        
        output_lower = event.get('output', '').lower()
        rule_lower = event.get('rule', '').lower()
        priority = event.get('priority', '').lower()
        
        # High priority events are likely malicious
        if priority in ['critical', 'error', 'warning']:
            # Check for malicious patterns
            for pattern_type, patterns in self.malicious_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in output_lower or pattern.lower() in rule_lower:
                        return True, pattern_type
        
        # Specific rule checks
        malicious_rules = [
            'shell_spawned',
            'read_sensitive_file',
            'write_below_binary',
            'setuid_setgid',
            'container_escape',
            'suspicious_process',
            'crypto_miners',
            'drop and execute',
        ]
        
        for rule in malicious_rules:
            if rule.lower() in rule_lower:
                return True, rule
        
        return False, None
    
    def analyze_window(self, events):
        """Analyze a time window and determine if it's benign or malicious"""
        if not events:
            return 'benign', 0, []
        
        malicious_count = 0
        malicious_types = []
        
        for event in events:
            is_malicious, pattern_type = self.is_malicious_event(event)
            if is_malicious:
                malicious_count += 1
                if pattern_type:
                    malicious_types.append(pattern_type)
        
        # If any malicious events, flag window as malicious
        if malicious_count > 0:
            return 'malicious', malicious_count, list(set(malicious_types))
        else:
            return 'benign', 0, []
    
    def read_falco_stderr(self):
        """Read new alerts from Falco container stderr"""
        try:
            # Get recent logs (last 10 seconds worth)
            result = subprocess.run(
                ['docker', 'logs', self.container_name, '--tail', '100', '--since', '12s'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if not result.stdout:
                return []
            
            # Parse JSON lines
            events = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and line.startswith('{'):
                    event = self.parse_falco_log_line(line)
                    if event:
                        # Check if we've seen this event before (by timestamp)
                        event_time = event.get('time', '')
                        if event_time and event_time != self.last_timestamp:
                            events.append(event)
                            self.last_timestamp = event_time
                            # Track containers
                            if event.get('container') and event['container'] != 'unknown':
                                self.monitored_containers.add(event['container'])
            
            return events
        except Exception as e:
            # Silently fail - Falco might not have new events
            return []
    
    def monitor_loop(self):
        """Main monitoring loop"""
        window_events = []
        window_start = datetime.now()
        
        while self.monitoring:
            current_time = datetime.now()
            
            # Read new events from Falco stderr
            new_events = self.read_falco_stderr()
            window_events.extend(new_events)
            
            # Check if window has elapsed
            elapsed = (current_time - window_start).total_seconds()
            
            if elapsed >= self.window_size:
                # Analyze window
                status, malicious_count, malicious_types = self.analyze_window(window_events)
                
                # Store window flag
                window_info = {
                    'start_time': window_start.isoformat(),
                    'end_time': current_time.isoformat(),
                    'status': status,
                    'event_count': len(window_events),
                    'malicious_count': malicious_count,
                    'malicious_types': malicious_types,
                    'containers': list(self.monitored_containers)
                }
                
                self.window_flags.append(window_info)
                
                # Print window analysis
                self.print_window_analysis(window_info)
                
                # Reset for next window
                window_events = []
                window_start = current_time
            
            time.sleep(0.5)  # Check every 0.5 seconds
    
    def print_window_analysis(self, window_info):
        """Print analysis of a time window"""
        start = datetime.fromisoformat(window_info['start_time']).strftime('%H:%M:%S')
        end = datetime.fromisoformat(window_info['end_time']).strftime('%H:%M:%S')
        status = window_info['status'].upper()
        event_count = window_info['event_count']
        malicious_count = window_info['malicious_count']
        
        # Color coding
        if status == 'MALICIOUS':
            status_symbol = '🔴'
            status_color = '\033[91m'  # Red
        else:
            status_symbol = '🟢'
            status_color = '\033[92m'  # Green
        
        reset_color = '\033[0m'
        
        print(f"\n{status_color}{status_symbol} [{start} - {end}] {status}{reset_color}")
        print(f"   Events: {event_count} | Malicious: {malicious_count}")
        
        if window_info['malicious_types']:
            print(f"   Types: {', '.join(window_info['malicious_types'])}")
        
        if window_info['containers']:
            print(f"   Containers: {', '.join(window_info['containers'])}")
    
    def get_summary(self):
        """Get summary of monitoring session"""
        total_windows = len(self.window_flags)
        malicious_windows = sum(1 for w in self.window_flags if w['status'] == 'malicious')
        benign_windows = total_windows - malicious_windows
        
        total_events = sum(w['event_count'] for w in self.window_flags)
        total_malicious_events = sum(w['malicious_count'] for w in self.window_flags)
        
        return {
            'total_windows': total_windows,
            'malicious_windows': malicious_windows,
            'benign_windows': benign_windows,
            'total_events': total_events,
            'total_malicious_events': total_malicious_events,
            'monitored_containers': list(self.monitored_containers),
            'windows': self.window_flags
        }
    
    def save_report(self, output_file):
        """Save monitoring report to file"""
        summary = self.get_summary()
        
        report = {
            'monitoring_session': {
                'start_time': self.window_flags[0]['start_time'] if self.window_flags else None,
                'end_time': self.window_flags[-1]['end_time'] if self.window_flags else None,
                'window_size_seconds': self.window_size,
                'source': 'falco_stderr'
            },
            'summary': {
                'total_windows': summary['total_windows'],
                'malicious_windows': summary['malicious_windows'],
                'benign_windows': summary['benign_windows'],
                'total_events': summary['total_events'],
                'total_malicious_events': summary['total_malicious_events'],
                'monitored_containers': summary['monitored_containers'],
            },
            'detailed_windows': summary['windows']
        }
        
        import json
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {output_file}")

