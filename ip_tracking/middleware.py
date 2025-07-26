from django.utils import timezone
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path
        # Block request if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden('Forbidden: Your IP is blocked.')
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=timezone.now(),
            path=path
        )
        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
