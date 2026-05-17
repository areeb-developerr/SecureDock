from rest_framework import serializers
from .models import FalcoEvent, Alert, MonitoringSession


class FalcoEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = FalcoEvent
        fields = '__all__'


class FalcoEventCreateSerializer(serializers.Serializer):
    """Accepts raw Falco JSON output and creates a FalcoEvent."""
    rule = serializers.CharField(max_length=255)
    priority = serializers.CharField(max_length=20)
    output = serializers.CharField()
    container_id = serializers.CharField(max_length=64, required=False, default='unknown')
    container_name = serializers.CharField(max_length=255, required=False, default='unknown')
    timestamp = serializers.DateTimeField(required=False)
    raw_json = serializers.JSONField(required=False, default=dict)
    output_fields = serializers.JSONField(required=False, default=dict)

    def create(self, validated_data):
        output_fields = validated_data.pop('output_fields', {})
        if output_fields:
            if validated_data.get('container_id', 'unknown') == 'unknown':
                validated_data['container_id'] = output_fields.get('container.id', 'unknown')
            if validated_data.get('container_name', 'unknown') == 'unknown':
                validated_data['container_name'] = output_fields.get('container.name', 'unknown')

        # Determine if malicious
        priority = validated_data.get('priority', '').lower()
        is_malicious = priority in ('critical', 'error', 'warning', 'notice')
        validated_data['is_malicious'] = is_malicious

        # Classify malicious type
        if is_malicious:
            validated_data['malicious_type'] = classify_event(validated_data)

        return FalcoEvent.objects.create(**validated_data)


def classify_event(event_data):
    """Classify the type of malicious event based on rule and output."""
    patterns = {
        'shell_spawned': ['shell', 'sh', 'bash', 'execve'],
        'sensitive_file': ['/etc/passwd', '/etc/shadow', 'sensitive file', 'read sensitive'],
        'write_binary': ['write_below_binary', '/bin/', '/sbin/', '/usr/bin/'],
        'privilege_escalation': ['setuid', 'setgid', 'sudo', 'su', 'privesc'],
        'container_escape': ['nsenter', 'mount', 'proc/1', 'privileged'],
        'crypto_mining': ['minerd', 'xmrig', 'crypto', 'miner'],
        'network_anomaly': ['outbound', 'unexpected_network', 'connection'],
        'reconnaissance': ['reconnaissance', 'whoami', 'id', 'uname'],
        'log_tampering': ['log', 'clear', 'tampering'],
        'ransomware': ['rename', 'delete', 'bulk file'],
    }

    text = (event_data.get('rule', '') + ' ' + event_data.get('output', '')).lower()
    for pattern_type, keywords in patterns.items():
        for keyword in keywords:
            if keyword in text:
                return pattern_type
    return 'unknown'


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'


class AlertUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ['status']


class MonitoringSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = MonitoringSession
        fields = '__all__'


class BulkEventSerializer(serializers.Serializer):
    """For bulk ingestion of Falco events."""
    events = FalcoEventCreateSerializer(many=True)

    def create(self, validated_data):
        events_data = validated_data['events']
        created = []
        for event_data in events_data:
            output_fields = event_data.pop('output_fields', {})
            if output_fields:
                if event_data.get('container_id', 'unknown') == 'unknown':
                    event_data['container_id'] = output_fields.get('container.id', 'unknown')
                if event_data.get('container_name', 'unknown') == 'unknown':
                    event_data['container_name'] = output_fields.get('container.name', 'unknown')

            priority = event_data.get('priority', '').lower()
            is_malicious = priority in ('critical', 'error', 'warning', 'notice')
            event_data['is_malicious'] = is_malicious
            if is_malicious:
                event_data['malicious_type'] = classify_event(event_data)

            created.append(FalcoEvent(**event_data))

        return FalcoEvent.objects.bulk_create(created)
