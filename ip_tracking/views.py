from django.shortcuts import render
from django.http import HttpResponse
from ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def login_authenticated(request):
    # Example login view for authenticated users
    return HttpResponse('Authenticated login attempt')

@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_anonymous(request):
    # Example login view for anonymous users
    return HttpResponse('Anonymous login attempt')
