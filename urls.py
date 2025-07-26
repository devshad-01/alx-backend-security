from django.contrib import admin
from django.urls import path
from ip_tracking import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/auth/', views.login_authenticated, name='login_authenticated'),
    path('login/anon/', views.login_anonymous, name='login_anonymous'),
]
