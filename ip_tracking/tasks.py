from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Q
from .models import RequestLog, SuspiciousIP

@shared_task
def detect_anomalies():
    now = timezone.now()
    one_hour_ago = now - timezone.timedelta(hours=1)
    # Flag IPs with >100 requests in the last hour
    high_volume_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )
    for entry in high_volume_ips:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry['ip_address'],
            reason='High request volume (>100/hr)'
        )
    # Flag IPs accessing sensitive paths
    sensitive_paths = ['/admin', '/login']
    suspicious_logs = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=sensitive_paths
    ).values('ip_address').distinct()
    for entry in suspicious_logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry['ip_address'],
            reason='Accessed sensitive path'
        )
