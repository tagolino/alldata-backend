from django.urls import path, include
from rest_framework import routers

from .views import LoginAPI, RegisterAPI

urlpatterns = [
    path('login', LoginAPI.as_view(), name='login'),
    path('register', RegisterAPI.as_view(), name='register'),
]
