from django.urls import path
from . import views

app_name = 'auth_app'

urlpatterns = [
    
    path('register/', views.register, name='register'),
    path('register/verify/', views.verify_register_otp, name='verify_register_otp'),
    path('register/resend-otp/', views.resend_register_otp, name='resend_register_otp'),

    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),

    path('request-otp/', views.request_otp_email, name='request_otp'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
]