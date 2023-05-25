from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import UserProfileSerializer
from ..models import Profile


class UserProfileAPIView(APIView):
    def get(self, request):
        instance = Profile.objects.get(user=request.user)
        serializer = UserProfileSerializer(instance,
                                           context={'request': request})
        return Response(serializer.data)
