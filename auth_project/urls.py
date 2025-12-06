from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

def home(request):
    
    if request.user.is_authenticated:
        return redirect('auth_app:dashboard')
    return redirect('auth_app:login')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('', include(('auth_app.urls', 'auth_app'), namespace='auth_app')),
]