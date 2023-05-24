from django.urls import path, include
from rest_framework import routers

from .views import LoginAPI

urlpatterns = [
    path('login', LoginAPI.as_view(), name='login'),
]
