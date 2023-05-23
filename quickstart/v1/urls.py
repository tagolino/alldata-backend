from django.urls import path, include
from rest_framework import routers

from .views import GroupViewSet, UserViewSet


router = routers.DefaultRouter(trailing_slash=False)
router.register(r'groups', GroupViewSet, basename='groups')
router.register(r'users', UserViewSet, basename='users')

urlpatterns = [
    path('', include(router.urls))
]
