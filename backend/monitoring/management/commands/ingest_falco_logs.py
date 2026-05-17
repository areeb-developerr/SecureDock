"""
Management command to ingest Falco log files into the database.
Tails the log file and creates FalcoEvent records + Alerts via context engine.

Usage:
    python manage.py ingest_falco_logs --log-file ../falco-logs/output.log
    python manage.py ingest_falco_logs --log-file ../falco-logs/output.log --tail
"""

import json
import time
import sys
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

from django.core.management.base import BaseCommand
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from monitoring.models import FalcoEvent, Alert
from monitoring.serializers import classify_event, FalcoEventSerializer, AlertSerializer


# Attack patterns (same as real_time_monitor.py context engine)
ATTACK_PATTERNS = {
    'REVERSE_SHELL': {
        'steps': [
            {'rule_match': 'shell', 'weight': 10},
            {'rule_match': 'outbound', 'weight': 10},
        ],
        'threshold': 20,
        'window': 30,
        'severity': 'critical',
        'desc': 'Application spawned a shell which immediately opened a network connection.',
    },
    'CRYPTO_MINING': {
        'steps': [
            {'rule_match': 'minerd', 'weight': 10},
            {'rule_match': 'shell', 'weight': 5},
            {'rule_match': 'outbound', 'weight': 5},
        ],
        'threshold': 10,
        'window': 60,
        'severity': 'critical',
        'desc': 'Container spawned shell and initiated connections consistent with mining.',
    },
    'DATA_EXFILTRATION': {
        'steps': [
            {'rule_match': 'sensitive', 'weight': 5},
            {'rule_match': 'outbound', 'weight': 5},
        ],
        'threshold': 10,
        'window': 60,
        'severity': 'high',
        'desc': 'Sensitive file read followed by outbound network connection.',
    },
    'WEB_SHELL': {
        'steps': [
            {'rule_match': 'webroot', 'weight': 5},
            {'rule_match': 'shell', 'weight': 10},
            {'rule_match': 'outbound', 'weight': 5},
        ],
        'threshold': 15,
        'window': 10,
        'severity': 'critical',
        'desc': 'Web server process spawned a shell and made connections.',
    },
    'PRIVILEGE_ESCALATION': {
        'steps': [
            {'rule_match': 'privileged', 'weight': 10},
            {'rule_match': 'shell', 'weight': 5},
            {'rule_match': 'sudo', 'weight': 5},
        ],
        'threshold': 15,
        'window': 10,
        'severity': 'high',
        'desc': 'Privileged container event detected followed by shell activity.',
    },
    'CONTAINER_ESCAPE': {
        'steps': [
            {'rule_match': 'privileged', 'weight': 10},
            {'rule_match': 'mount', 'weight': 10},
            {'rule_match': 'sensitive kernel', 'weight': 10},
        ],
        'threshold': 10,
        'window': 30,
        'severity': 'critical',
        'desc': 'Potential container escape or privileged activity detected.',
    },
    'RECONNAISSANCE_SPREE': {
        'steps': [
            {'rule_match': 'reconnaissance', 'weight': 5},
            {'rule_match': 'network tool', 'weight': 2},
            {'rule_match': 'id', 'weight': 1},
            {'rule_match': 'whoami', 'weight': 1},
        ],
        'threshold': 5,
        'window': 60,
        'severity': 'medium',
        'desc': 'Multiple reconnaissance activities detected.',
    },
    'LOG_TAMPERING': {
        'steps': [
            {'rule_match': 'log', 'weight': 10},
            {'rule_match': 'clear', 'weight': 10},
        ],
        'threshold': 10,
        'window': 10,
        'severity': 'high',
        'desc': 'Security log clearing or tampering detected.',
    },
}


class ContextEngine:
    """Detects attack patterns from sequences of events."""

    def __init__(self):
        self.state = defaultdict(lambda: defaultdict(list))

    def process_event(self, event_data):
        triggered = []
        container = event_data.get('container_name', 'unknown')
        if container == 'unknown':
            return []

        target_text = (
            event_data.get('rule', '') + ' ' + event_data.get('output', '')
        ).lower()

        now = timezone.now()

        for pattern_name, config in ATTACK_PATTERNS.items():
            matches = False
            for step in config['steps']:
                if step['rule_match'].lower() in target_text:
                    matches = True
                    break

            if matches:
                self.state[container][pattern_name].append({
                    'timestamp': now,
                    'rule': event_data.get('rule', ''),
                })

                window_start = now - timedelta(seconds=config['window'])
                self.state[container][pattern_name] = [
                    e for e in self.state[container][pattern_name]
                    if e['timestamp'] > window_start
                ]

                score = 0
                rules = [e['rule'] for e in self.state[container][pattern_name]]
                for step in config['steps']:
                    if any(step['rule_match'] in r.lower() for r in rules):
                        score += step['weight']

                if score >= config['threshold']:
                    triggered.append({
                        'pattern': pattern_name,
                        'desc': config['desc'],
                        'severity': config['severity'],
                        'container': container,
                    })
                    self.state[container][pattern_name] = []

        return triggered


class Command(BaseCommand):
    help = 'Ingest Falco log file into the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--log-file',
            type=str,
            required=True,
            help='Path to Falco output.log file',
        )
        parser.add_argument(
            '--tail',
            action='store_true',
            help='Tail the log file continuously (like tail -f)',
        )

    def handle(self, *args, **options):
        log_path = Path(options['log_file'])
        tail_mode = options['tail']

        if not log_path.exists():
            self.stderr.write(self.style.ERROR(f'Log file not found: {log_path}'))
            return

        self.stdout.write(self.style.SUCCESS(f'Ingesting from: {log_path}'))

        context_engine = ContextEngine()
        events_created = 0
        alerts_created = 0

        if tail_mode:
            self.stdout.write('Tail mode: watching for new lines...')
            events_created, alerts_created = self._tail_file(
                log_path, context_engine
            )
        else:
            # Process entire file
            with open(log_path, 'r') as f:
                for line in f:
                    result = self._process_line(line, context_engine)
                    if result:
                        ec, ac = result
                        events_created += ec
                        alerts_created += ac

        self.stdout.write(
            self.style.SUCCESS(
                f'Done. Events: {events_created}, Alerts: {alerts_created}'
            )
        )

    def _tail_file(self, log_path, context_engine):
        """Continuously tail the log file."""
        events_created = 0
        alerts_created = 0
        last_pos = 0

        # Start from end of file
        if log_path.stat().st_size > 0:
            last_pos = log_path.stat().st_size

        self.stdout.write(f'Starting from position {last_pos}')

        try:
            while True:
                current_size = log_path.stat().st_size
                if current_size < last_pos:
                    last_pos = 0  # File was truncated

                if current_size > last_pos:
                    with open(log_path, 'r') as f:
                        f.seek(last_pos)
                        while True:
                            line = f.readline()
                            if not line:
                                break
                            
                            # Only process complete lines (ending with newline)
                            if not line.endswith('\n'):
                                f.seek(f.tell() - len(line))
                                break
                                
                            result = self._process_line(line, context_engine)
                            if result:
                                ec, ac = result
                                events_created += ec
                                alerts_created += ac
                        last_pos = f.tell()

                time.sleep(1)
        except KeyboardInterrupt:
            self.stdout.write('\nStopping tail...')

        return events_created, alerts_created

    def _process_line(self, line, context_engine):
        """Process a single log line."""
        line = line.strip()
        if not line or not line.startswith('{'):
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # Extract fields
        rule = data.get('rule', '')
        priority = data.get('priority', '').lower()
        output = data.get('output', '')
        output_fields = data.get('output_fields', {})
        container_id = output_fields.get('container.id') or 'unknown'
        container_name = output_fields.get('container.name') or 'unknown'
        time_str = data.get('time', '')

        # Skip non-container events: host-level, unknown, or Falco's own container
        skip_containers = ('falco-monitor', 'falco-monitor-vulnerable', 'host', 'unknown', '')
        if container_name in skip_containers:
            return None

        # Parse timestamp
        ts = timezone.now()
        if time_str:
            try:
                ts = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                if ts.tzinfo is None:
                    ts = timezone.make_aware(ts)
            except (ValueError, TypeError):
                pass

        # Determine if malicious
        is_malicious = priority in ('critical', 'error', 'warning', 'notice')
        event_data = {
            'rule': rule,
            'priority': priority,
            'output': output,
            'container_id': container_id,
            'container_name': container_name,
            'raw_json': data,
        }
        malicious_type = classify_event(event_data) if is_malicious else ''

        # Create event
        event = FalcoEvent.objects.create(
            rule=rule,
            priority=priority,
            output=output,
            container_id=container_id,
            container_name=container_name,
            timestamp=ts,
            raw_json=data,
            is_malicious=is_malicious,
            malicious_type=malicious_type,
        )

        # Broadcast via WebSocket
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'events',
                {
                    'type': 'event_message',
                    'data': {
                        'kind': 'event',
                        'event': FalcoEventSerializer(event).data,
                    },
                },
            )
        except Exception:
            pass

        events_created = 1
        alerts_created = 0

        # Check context engine for alerts
        triggered = context_engine.process_event({
            'rule': rule,
            'output': output,
            'container_name': container_name,
        })

        for alert_data in triggered:
            alert = Alert.objects.create(
                pattern=alert_data['pattern'],
                description=alert_data['desc'],
                severity=alert_data['severity'],
                container_name=container_name,
                container_id=container_id,
                evidence=[{
                    'rule': rule,
                    'output': output[:200],
                    'time': ts.isoformat(),
                }],
            )
            alerts_created += 1
            self.stdout.write(
                self.style.WARNING(
                    f'  ALERT: {alert_data["pattern"]} on {container_name}'
                )
            )

            # Broadcast alert
            try:
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    'events',
                    {
                        'type': 'event_message',
                        'data': {
                            'kind': 'alert',
                            'alert': AlertSerializer(alert).data,
                        },
                    },
                )
            except Exception:
                pass

        return events_created, alerts_created
