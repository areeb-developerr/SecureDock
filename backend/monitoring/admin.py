from django.contrib import admin
from .models import FalcoEvent, Alert, MonitoringSession


@admin.register(FalcoEvent)
class FalcoEventAdmin(admin.ModelAdmin):
    list_display = ('rule', 'priority', 'container_name', 'is_malicious', 'timestamp')
    list_filter = ('priority', 'is_malicious', 'container_name')
    search_fields = ('rule', 'output', 'container_name')
    readonly_fields = ('raw_json',)


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('pattern', 'severity', 'status', 'container_name', 'created_at')
    list_filter = ('severity', 'status')
    search_fields = ('pattern', 'description', 'container_name')


@admin.register(MonitoringSession)
class MonitoringSessionAdmin(admin.ModelAdmin):
    list_display = ('id', 'started_at', 'ended_at', 'total_events', 'malicious_events', 'is_active')
    list_filter = ('is_active',)
