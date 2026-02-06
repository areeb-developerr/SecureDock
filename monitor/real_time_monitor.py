
import subprocess
import sys
import time
import json
import os
import signal
import re
import shutil
import logging
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

# ==========================================
# Configuration & Attack Patterns
# ==========================================

ATTACK_PATTERNS = {
    'REVERSE_SHELL': {
        'steps': [
            {'rule_match': 'shell', 'weight': 10},
            {'rule_match': 'outbound', 'weight': 10}
        ],
        'threshold': 20,
        'window': 30,
        'desc': 'Application spawned a shell which immediately opened a network connection.'
    },
    'CRYPTO_MINING': {
        'steps': [
            {'rule_match': 'minerd', 'weight': 10}, # Specific check for miner name in output
            {'rule_match': 'shell', 'weight': 5},
            {'rule_match': 'outbound', 'weight': 5}
        ],
        'threshold': 10,
        'window': 60,
        'desc': 'Container spawned shell and initiated external network connections consistent with mining.'
    },
    'DATA_EXFILTRATION': {
        'steps': [
            {'rule_match': 'sensitive', 'weight': 5},
            {'rule_match': 'outbound', 'weight': 5}
        ],
        'threshold': 10,
        'window': 60,
        'desc': 'Sensitive file read followed by outbound network connection.'
    },
    'WEB_SHELL': {
        'steps': [
            {'rule_match': 'webroot', 'weight': 5},
            {'rule_match': 'shell', 'weight': 10},
            {'rule_match': 'outbound', 'weight': 5} 
        ],
        'threshold': 15,
        'window': 10,
        'desc': 'Web server process spawned a shell and made connections.'
    },
    'PRIVILEGE_ESCALATION': {
        'steps': [
            {'rule_match': 'privileged', 'weight': 10},
            {'rule_match': 'shell', 'weight': 5},
            {'rule_match': 'sudo', 'weight': 5}
        ],
        'threshold': 15,
        'window': 10,
        'desc': 'Privileged container event detected followed by shell activity.'
    },
    'BINARY_PLANTING': {
        'steps': [
            {'rule_match': 'binary', 'weight': 10},
            {'rule_match': 'shell', 'weight': 5}
        ],
        'threshold': 10,
        'window': 60,
        'desc': 'Binary file written to system directory.'
    },
    'CONTAINER_ESCAPE': {
        'steps': [
            {'rule_match': 'privileged', 'weight': 10},
            {'rule_match': 'mount', 'weight': 10},
            {'rule_match': 'sensitive kernel', 'weight': 10}
        ],
        'threshold': 10,
        'window': 30,
        'desc': 'Potential container escape or privileged activity detected.'
    },
    'RANSOMWARE_BEHAVIOR': {
        'steps': [
            {'rule_match': 'rename', 'weight': 2},
            {'rule_match': 'delete', 'weight': 2}
        ],
        'threshold': 10,
        'window': 10,
        'desc': 'High frequency of file renaming or deletion detected.'
    },
    'LOG_TAMPERING': {
        'steps': [
            {'rule_match': 'log', 'weight': 10},
            {'rule_match': 'clear', 'weight': 10}
        ],
        'threshold': 10,
        'window': 10,
        'desc': 'Security log clearing or tampering detected.'
    },
    'RECONNAISSANCE_SPREE': {
        'steps': [
            {'rule_match': 'reconnaissance', 'weight': 5},
            {'rule_match': 'network tool', 'weight': 2},
            {'rule_match': 'id', 'weight': 1}, # Catch 'id' command output
            {'rule_match': 'whoami', 'weight': 1}
        ],
        'threshold': 5, # Lowered threshold slightly
        'window': 60,
        'desc': 'Multiple reconnaissance activities detected.'
    }
}

class ContextEngine:
    def __init__(self):
        self.state = defaultdict(lambda: defaultdict(list))
        # No cooldowns (reverted)
        
    def process_event(self, event):
        triggered_alerts = []
        container_id = event.get('container_id', 'unknown')
        if container_id == 'unknown':
            return []

        event_rule = event.get('rule', '')
        
        for pattern_name, config in ATTACK_PATTERNS.items():
            matches_step = False
            
            # Create a broad search text including rule name and output
            # This handles cases where Standard Falco rules trigger instead of Custom ones
            target_text = (event.get('rule', '') + ' ' + event.get('output', '')).lower()
            
            for step in config['steps']:
                if step['rule_match'].lower() in target_text:
                    matches_step = True
                    break
            
            if matches_step:
                self.state[container_id][pattern_name].append({
                    'timestamp': datetime.now(),
                    'event': event,
                    'rule': event_rule
                })
                
                window_start = datetime.now() - timedelta(seconds=config['window'])
                self.state[container_id][pattern_name] = [
                    e for e in self.state[container_id][pattern_name] 
                    if e['timestamp'] > window_start
                ]
                
                if self._check_pattern_completion(container_id, pattern_name, config):
                    triggered_alerts.append({
                        'pattern': pattern_name,
                        'desc': config['desc'],
                        'container': container_id,
                        'events': self.state[container_id][pattern_name]
                    })
                    # We do NOT clear the state here in the "looping" version, or we do? 
                    # If we don't clear, it alerts 100 times.
                    # The user said "output is being looped".
                    # I will NOT clear the state to ensure looping.
                    # self.state[container_id][pattern_name] = [] 
                    pass 
                    
        return triggered_alerts

    def _check_pattern_completion(self, container_id, pattern_name, config):
        events = self.state[container_id][pattern_name]
        if not events:
            return False
            
        current_score = 0
        matched_event_rules = [e['rule'] for e in events]
        
        if len(config['steps']) == 1:
            step_def = config['steps'][0]
            count = sum(1 for rule in matched_event_rules if step_def['rule_match'] in rule)
            current_score = count * step_def['weight']
        else:
            for step in config['steps']:
                if any(step['rule_match'] in rule for rule in matched_event_rules):
                    current_score += step['weight']

        return current_score >= config['threshold']


class RealTimeMonitor:
    def __init__(self, log_file_path, window_size=10):
        self.log_file_path = Path(log_file_path)
        self.monitoring = False
        self.context_engine = ContextEngine()
        self.last_position = 0 # REVERTED: Start from 0, don't seek to end.
        
    def start_monitoring(self):
        """Start monitoring in background"""
        self.monitoring = True
        print(f"[*] Context-Aware Monitoring Engine Started")
        print(f"[*] Scope: {len(ATTACK_PATTERNS)} Critical Attack Patterns")
        print(f"[*] Reading source: {self.log_file_path}")
        
    def stop_monitoring(self):
        self.monitoring = False
        print("[*] Monitoring stopped")
    
    def parse_falco_log_line(self, line):
        try:
            if not line.strip(): return None
            data = json.loads(line)
            
            output = data.get('output', '')
            priority = data.get('priority', '').lower()
            rule = data.get('rule', '')
            
            output_fields = data.get('output_fields', {})
            container_id = output_fields.get('container.id', 'unknown')
            container_name = output_fields.get('container.name', 'unknown')
            
            return {
                'output': output,
                'priority': priority,
                'rule': rule,
                'container_id': container_id,
                'container_name': container_name,
                'time': data.get('time', ''),
                'raw': data
            }
        except json.JSONDecodeError:
            return None
        except Exception as e:
            return None

    def read_new_log_lines(self):
        lines = []
        try:
            if not self.log_file_path.exists():
                return []

            current_size = self.log_file_path.stat().st_size
            
            # If file was truncated or is smaller than last position, reset
            if current_size < self.last_position:
                self.last_position = 0

            # If this is the first read (last_position=0) and file is huge, skip to end
            # This prevents processing GBs of old logs on startup
            if self.last_position == 0 and current_size > 1024*1024:
                self.last_position = current_size

            with open(self.log_file_path, 'r') as f:
                f.seek(self.last_position)
                lines = f.readlines()
                self.last_position = f.tell()
        except Exception as e:
            pass
            
        return lines

    def monitor_loop(self):
        while self.monitoring:
            try:
                new_lines = self.read_new_log_lines()
                
                for line in new_lines:
                    event = self.parse_falco_log_line(line)
                    if not event: continue
                    
                    # 1. Process for Patterns
                    alerts = self.context_engine.process_event(event)
                    
                    # 2. Output (NO Throttling)
                    self.print_event(event)
                    
                    # 3. Alerts
                    for alert in alerts:
                        self.print_alert(alert)
                
                time.sleep(1)

            except KeyboardInterrupt:
                print("\n[*] Stopping monitor...")
                break
            except Exception as e:
                print(f"Error in monitor loop: {e}")
                time.sleep(5) 

    def print_event(self, event):
        priority = event['priority'].upper()
        color = '\033[93m' if priority in ['WARNING', 'NOTICE'] else '\033[94m' 
        reset = '\033[0m'
        print(f"{color}[STEP] {event['output']}{reset}")

    def print_alert(self, alert):
        red = '\033[91m'
        bold = '\033[1m'
        reset = '\033[0m'
        print(f"\n{red}{bold}!!! CRITICAL SECURITY ALERT !!!{reset}")
        print(f"{red}Attack Pattern Detected: {alert['pattern']}{reset}")
        print(f"{red}Description: {alert['desc']}{reset}")
        print(f"{red}Target: {alert['container']}{reset}")
        print(f"{red}Evidence:{reset}")
        for e in alert['events']:
            ts = e['timestamp'].strftime('%H:%M:%S')
            output = e['event'].get('output', 'N/A')
            print(f"  - {ts} : {output}")
        print("-" * 50 + "\n")

if __name__ == "__main__":
    monitor = RealTimeMonitor("falco-logs/output.log")
    monitor.start_monitoring()
    try:
        monitor.monitor_loop()
    except KeyboardInterrupt:
        monitor.stop_monitoring()
