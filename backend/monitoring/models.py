from django.db import models
from django.utils import timezone


class FalcoEvent(models.Model):
    """Individual Falco alert event."""

    PRIORITY_CHOICES = [
        ('emergency', 'Emergency'),
        ('alert', 'Alert'),
        ('critical', 'Critical'),
        ('error', 'Error'),
        ('warning', 'Warning'),
        ('notice', 'Notice'),
        ('informational', 'Informational'),
        ('debug', 'Debug'),
    ]

    rule = models.CharField(max_length=255, db_index=True)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, db_index=True)
    output = models.TextField()
    container_id = models.CharField(max_length=64, default='unknown', db_index=True)
    container_name = models.CharField(max_length=255, default='unknown', db_index=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    raw_json = models.JSONField(default=dict, blank=True)
    is_malicious = models.BooleanField(default=False, db_index=True)
    malicious_type = models.CharField(max_length=100, blank=True, default='')

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp', 'container_name']),
            models.Index(fields=['is_malicious', '-timestamp']),
        ]

    def __str__(self):
        return f"[{self.priority}] {self.rule} - {self.container_name} @ {self.timestamp}"


class Alert(models.Model):
    """Higher-level alert from context engine pattern matching."""

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('dismissed', 'Dismissed'),
    ]

    pattern = models.CharField(max_length=100, db_index=True)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active', db_index=True)
    container_id = models.CharField(max_length=64, default='unknown')
    container_name = models.CharField(max_length=255, default='unknown', db_index=True)
    evidence = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.pattern} - {self.container_name}"


class MonitoringSession(models.Model):
    """Tracks a monitoring session."""

    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    total_events = models.IntegerField(default=0)
    malicious_events = models.IntegerField(default=0)
    source = models.CharField(max_length=50, default='falco_log')
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        status = "Active" if self.is_active else "Ended"
        return f"Session {self.id} ({status}) - {self.started_at}"
