from django.urls import path, include
from rest_framework import routers

from .views import UserProfileAPIView


router = routers.DefaultRouter(trailing_slash=False)

urlpatterns = [
    path('profile', UserProfileAPIView.as_view(), name='profile'),
]
