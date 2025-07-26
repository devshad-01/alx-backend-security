from django.utils import timezone
from django.http import HttpResponseForbidden
from django.core.cache import cache
from ipgeolocation import IpGeolocationAPI
from .models import RequestLog, BlockedIP

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.geo_api = IpGeolocationAPI()

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path
        # Block request if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden('Forbidden: Your IP is blocked.')
        # Geolocation caching (24 hours)
        geo_cache_key = f'geo_{ip_address}'
        geo_data = cache.get(geo_cache_key)
        if not geo_data:
            geo_data = self.geo_api.get_geolocation(ip_address)
            cache.set(geo_cache_key, geo_data, 60 * 60 * 24)  # 24 hours
        country = geo_data.get('country_name', '') if geo_data else ''
        city = geo_data.get('city', '') if geo_data else ''
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=timezone.now(),
            path=path,
            country=country,
            city=city
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
