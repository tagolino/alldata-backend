from django.urls import path, include
from rest_framework import routers

from .views import ForgetPasswordAPI, LoginAPI, LogoutAPI, RegisterAPI

urlpatterns = [
    path('forget-password', ForgetPasswordAPI.as_view(), name='forget-password'),
    path('login', LoginAPI.as_view(), name='login'),
    path('logout', LogoutAPI.as_view(), name='logout'),
    path('register', RegisterAPI.as_view(), name='register'),
]
