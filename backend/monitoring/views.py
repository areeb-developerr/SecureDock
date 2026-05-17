from rest_framework import viewsets, status, permissions
from rest_framework.decorators import api_view, action, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.db.models.functions import TruncHour, TruncDay
from django.utils import timezone
from datetime import timedelta
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from .models import FalcoEvent, Alert, MonitoringSession
from .serializers import (
    FalcoEventSerializer,
    FalcoEventCreateSerializer,
    AlertSerializer,
    AlertUpdateSerializer,
    MonitoringSessionSerializer,
    BulkEventSerializer,
)


# ─── Auth Views ────────────────────────────────────────────────

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username', '')
        password = request.data.get('password', '')

        if not username or not password:
            return Response(
                {'error': 'Username and password required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return Response({
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_staff': user.is_staff,
                },
            })
        return Response(
            {'error': 'Invalid credentials'},
            status=status.HTTP_401_UNAUTHORIZED,
        )


class LogoutView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        logout(request)
        return Response({'message': 'Logged out'})


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username', '')
        password = request.data.get('password', '')
        email = request.data.get('email', '')

        if not username or not password:
            return Response(
                {'error': 'Username and password required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(username=username).exists():
            return Response(
                {'error': 'Username already exists'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.create_user(username=username, password=password, email=email)
        login(request, user)
        return Response({
            'message': 'Registration successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
            },
        }, status=status.HTTP_201_CREATED)


class CurrentUserView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        if request.user.is_authenticated:
            return Response({
                'authenticated': True,
                'user': {
                    'id': request.user.id,
                    'username': request.user.username,
                    'email': request.user.email,
                    'is_staff': request.user.is_staff,
                },
            })
        return Response({'authenticated': False}, status=status.HTTP_200_OK)


# ─── Event Views ───────────────────────────────────────────────

class FalcoEventViewSet(viewsets.ModelViewSet):
    queryset = FalcoEvent.objects.all()
    serializer_class = FalcoEventSerializer
    permission_classes = [permissions.AllowAny]

    def get_serializer_class(self):
        if self.action == 'create':
            return FalcoEventCreateSerializer
        return FalcoEventSerializer

    def get_queryset(self):
        qs = FalcoEvent.objects.all()
        container = self.request.query_params.get('container')
        priority = self.request.query_params.get('priority')
        is_malicious = self.request.query_params.get('is_malicious')
        hours = self.request.query_params.get('hours')

        if container:
            qs = qs.filter(container_name__icontains=container)
        if priority:
            qs = qs.filter(priority=priority.lower())
        if is_malicious is not None:
            qs = qs.filter(is_malicious=is_malicious.lower() == 'true')
        if hours:
            since = timezone.now() - timedelta(hours=int(hours))
            qs = qs.filter(timestamp__gte=since)
        return qs

    def perform_create(self, serializer):
        event = serializer.save()
        # Broadcast via WebSocket
        _broadcast_event(event)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Aggregated event statistics."""
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        qs = FalcoEvent.objects.filter(timestamp__gte=since)

        total = qs.count()
        malicious = qs.filter(is_malicious=True).count()

        by_priority = list(
            qs.values('priority')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        by_container = list(
            qs.values('container_name')
            .annotate(
                count=Count('id'),
                malicious_count=Count('id', filter=Q(is_malicious=True)),
            )
            .order_by('-count')
        )

        by_type = list(
            qs.filter(is_malicious=True)
            .values('malicious_type')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # Timeline: events per hour
        timeline = list(
            qs.annotate(hour=TruncHour('timestamp'))
            .values('hour')
            .annotate(
                total=Count('id'),
                malicious=Count('id', filter=Q(is_malicious=True)),
            )
            .order_by('hour')
        )

        return Response({
            'total_events': total,
            'malicious_events': malicious,
            'benign_events': total - malicious,
            'by_priority': by_priority,
            'by_container': by_container,
            'by_type': by_type,
            'timeline': timeline,
        })

    @action(detail=False, methods=['post'])
    def bulk(self, request):
        """Bulk create events."""
        serializer = BulkEventSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        events = serializer.save()
        for event in events:
            _broadcast_event(event)
        return Response(
            {'created': len(events)},
            status=status.HTTP_201_CREATED,
        )


# ─── Alert Views ───────────────────────────────────────────────

class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [permissions.AllowAny]

    def get_serializer_class(self):
        if self.action in ('partial_update', 'update'):
            return AlertUpdateSerializer
        return AlertSerializer

    def get_queryset(self):
        qs = Alert.objects.all()
        severity = self.request.query_params.get('severity')
        alert_status = self.request.query_params.get('status')
        container = self.request.query_params.get('container')
        hours = self.request.query_params.get('hours')

        if severity:
            qs = qs.filter(severity=severity.lower())
        if alert_status:
            qs = qs.filter(status=alert_status.lower())
        if container:
            qs = qs.filter(container_name__icontains=container)
        if hours:
            since = timezone.now() - timedelta(hours=int(hours))
            qs = qs.filter(created_at__gte=since)
        return qs

    def perform_create(self, serializer):
        alert = serializer.save()
        _broadcast_alert(alert)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Alert statistics."""
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        qs = Alert.objects.filter(created_at__gte=since)

        return Response({
            'total': qs.count(),
            'active': qs.filter(status='active').count(),
            'investigating': qs.filter(status='investigating').count(),
            'resolved': qs.filter(status='resolved').count(),
            'by_severity': list(
                qs.values('severity')
                .annotate(count=Count('id'))
                .order_by('-count')
            ),
            'by_pattern': list(
                qs.values('pattern')
                .annotate(count=Count('id'))
                .order_by('-count')
            ),
        })


# ─── Container Views ──────────────────────────────────────────

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def container_list(request):
    """List all monitored containers with activity summaries."""
    hours = int(request.query_params.get('hours', 24))
    since = timezone.now() - timedelta(hours=hours)

    containers_data = (
        FalcoEvent.objects.filter(timestamp__gte=since)
        .exclude(container_name='unknown')
        .values('container_name', 'container_id')
        .annotate(
            total_events=Count('id'),
            malicious_events=Count('id', filter=Q(is_malicious=True)),
        )
        .order_by('-total_events')
    )

    results = []
    for c in containers_data:
        malicious = c['malicious_events']
        total = c['total_events']
        if malicious > 5:
            health = 'malicious'
        elif malicious > 0:
            health = 'warning'
        else:
            health = 'healthy'

        last_event = (
            FalcoEvent.objects
            .filter(container_name=c['container_name'])
            .first()
        )

        results.append({
            'id': c['container_id'],
            'name': c['container_name'],
            'status': 'running',
            'health': health,
            'total_events': total,
            'malicious_events': malicious,
            'last_activity': last_event.timestamp.isoformat() if last_event else None,
        })

    return Response(results)


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def container_detail(request, container_id):
    """Container detail with recent events."""
    events = FalcoEvent.objects.filter(
        Q(container_id=container_id) | Q(container_name=container_id)
    )[:100]

    if not events.exists():
        return Response({'error': 'Container not found'}, status=404)

    first = events.last()
    latest = events.first()

    malicious_count = events.filter(is_malicious=True).count()
    total = events.count()
    health = 'malicious' if malicious_count > 5 else ('warning' if malicious_count > 0 else 'healthy')

    return Response({
        'id': first.container_id,
        'name': first.container_name,
        'status': 'running',
        'health': health,
        'total_events': total,
        'malicious_events': malicious_count,
        'first_seen': first.timestamp.isoformat(),
        'last_seen': latest.timestamp.isoformat(),
        'recent_events': FalcoEventSerializer(events[:50], many=True).data,
    })


# ─── Dashboard View ───────────────────────────────────────────

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def dashboard(request):
    """Aggregated dashboard data for the main overview page."""
    hours = int(request.query_params.get('hours', 24))
    since = timezone.now() - timedelta(hours=hours)

    events_qs = FalcoEvent.objects.filter(timestamp__gte=since)
    alerts_qs = Alert.objects.filter(created_at__gte=since)

    total_events = events_qs.count()
    malicious_events = events_qs.filter(is_malicious=True).count()
    total_alerts = alerts_qs.count()
    active_alerts = alerts_qs.filter(status='active').count()

    # Unique containers
    containers = (
        events_qs.exclude(container_name='unknown')
        .values('container_name')
        .annotate(
            total=Count('id'),
            malicious=Count('id', filter=Q(is_malicious=True)),
        )
        .order_by('-total')
    )

    container_summary = []
    running = 0
    warning_count = 0
    malicious_containers = 0
    for c in containers:
        m = c['malicious']
        if m > 5:
            health = 'malicious'
            malicious_containers += 1
        elif m > 0:
            health = 'warning'
            warning_count += 1
        else:
            health = 'healthy'
            running += 1
        container_summary.append({
            'name': c['container_name'],
            'total': c['total'],
            'malicious': c['malicious'],
            'health': health,
        })

    # Recent alerts
    recent_alerts = AlertSerializer(alerts_qs[:5], many=True).data

    # Timeline for chart
    timeline = list(
        events_qs.annotate(hour=TruncHour('timestamp'))
        .values('hour')
        .annotate(
            total=Count('id'),
            malicious=Count('id', filter=Q(is_malicious=True)),
            benign=Count('id', filter=Q(is_malicious=False)),
        )
        .order_by('hour')
    )

    # Attack type distribution
    attack_types = list(
        events_qs.filter(is_malicious=True)
        .values('malicious_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    # System health percentage
    system_health = round(
        ((total_events - malicious_events) / total_events * 100) if total_events > 0 else 100.0,
        1,
    )

    return Response({
        'stats': {
            'total_containers': len(container_summary),
            'malicious_detected': malicious_containers,
            'system_health': system_health,
            'alerts_24h': total_alerts,
            'total_events': total_events,
            'malicious_events': malicious_events,
        },
        'container_status': {
            'running': running,
            'warning': warning_count,
            'malicious': malicious_containers,
        },
        'containers': container_summary,
        'recent_alerts': recent_alerts,
        'timeline': timeline,
        'attack_types': attack_types,
    })


# ─── Logs View ─────────────────────────────────────────────────

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def logs_view(request):
    """Paginated log stream with search and filter."""
    qs = FalcoEvent.objects.all()

    search = request.query_params.get('search')
    severity = request.query_params.get('severity')
    container = request.query_params.get('container')
    limit = int(request.query_params.get('limit', 100))

    if search:
        qs = qs.filter(
            Q(output__icontains=search)
            | Q(rule__icontains=search)
            | Q(container_name__icontains=search)
        )
    if severity:
        qs = qs.filter(priority=severity.lower())
    if container:
        qs = qs.filter(container_name__icontains=container)

    events = qs[:limit]
    return Response(FalcoEventSerializer(events, many=True).data)


# ─── WebSocket broadcast helpers ──────────────────────────────

def _broadcast_event(event):
    """Broadcast a new event to all connected WebSocket clients."""
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
        pass  # Channel layer may not be available


def _broadcast_alert(alert):
    """Broadcast a new alert to all connected WebSocket clients."""
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
