import hashlib
import random
import string

from datetime import datetime
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.db.models import Q
from django.http import JsonResponse
from django.utils import timezone
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.translation import gettext_lazy as _
from oauth2_provider.models import Application, AccessToken, RefreshToken
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import ForgetPasswordSerializer, RegisterSerializer, UserLoginSerializer
from alldata_backend.utils import get_client_ip
from appuser.models import Profile


class CustomModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(**kwargs)
        except User.DoesNotExist:
            return None

        if user.username:
            return super().authenticate(request, user.username, password, **kwargs)
        return None


class AuthToken:
    def __init__(self, user: User) -> None:
        super().__init__()
        self.user = user

    def create_token(self):
        """
        @brief
            A more flexible way of handling and creating Oauth AccessTokens
        """

        expire_seconds = settings.OAUTH2_PROVIDER.get('ACCESS_TOKEN_EXPIRE_SECONDS', 25920000)
        scopes = settings.OAUTH2_PROVIDER['SCOPES']

        # Get application based on user role
        application = Application.objects.get(name='dashboard')

        # delete old tokens, if any
        self.delete_tokens()

        expires = timezone.localtime() + timezone. \
            timedelta(seconds=expire_seconds)

        date_joined = self.user.date_joined.strftime('%Y-%m-%d %H:%M:%S')
        user_token = self.generate_token(self.user.username, date_joined)

        access_token = AccessToken.objects.create(user=self.user,
                                                  application=application,
                                                  token=user_token,
                                                  expires=expires,
                                                  scope=scopes)

        refresh_token = RefreshToken.objects.create(user=self.user,
                                                    application=application,
                                                    token=user_token,
                                                    access_token=access_token)

        token = {
            'access_token': access_token.token,
            'token_type': 'Bearer',
            'expires_in': expires.strftime('%Y-%m-%d %H:%M:%S'),
            'refresh_token': refresh_token.token,
            'type': 'staff',
            'scope': scopes
        }
        
        print('XXXX')

        return token

    def generate_token(self, string_0, string_1):
        """
        @brief
            Returns a random string to serve as an Oauth AccessToken value
        """

        salt = self.random_token_generator(4)
        token = f'{string_0}.{string_1}.{salt}'

        return hashlib.md5(token.encode('utf-8')).hexdigest()

    def random_token_generator(self, length):
        seq = string.ascii_lowercase + string.digits

        return ''.join(random.choices(seq, k=length))

    def delete_tokens(self):
        AccessToken.objects.filter(user=self.user).delete()
        RefreshToken.objects.filter(user=self.user).delete()

    def check_active_session(self):
        application = Application.objects.get(name='dashboard')

        try:
            access_token = AccessToken.objects.get(user=self.user,
                                                   application=application)

            refresh_token = RefreshToken.objects.get(user=self.user,
                                                     application=application)
        except Exception:
            return None
        else:
            return {
                'access_token': access_token.token,
                'token_type': 'Bearer',
                'expires_in': access_token.expires,
                'refresh_token': refresh_token.token,
                'type': 'staff',
                'scope': access_token.scope
            }


class LoginAPI(CustomModelBackend, APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        user = None
        error_msg = None
        data = request.data.copy()

        serializer = UserLoginSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        try:
            if data.get('email'):
                error_msg = 'Invalid E-mail/password.'
                user = self.authenticate(request, email=data['email'],
                                         password=data['password'])
        except MultiValueDictKeyError:
            return Response({'errors': _('Login is not allowed.')},
                            status=status.HTTP_401_UNAUTHORIZED)

        if user is not None:
            user.is_online = True
            user.last_login_at = datetime.now()
            user.save()

            auth_token = AuthToken(user)
            token = auth_token.check_active_session()

            if not token:
                token = auth_token.create_token()

            access_token_obj = AccessToken.objects.get(
                token=token['access_token'])
            access_token_obj.expires = access_token_obj. \
                expires.replace(year=2050)
            access_token_obj.save()

            response = JsonResponse({'msg': 'Successfully logged in to the system.', 'data': token},
                                    status=status.HTTP_200_OK)
            response.set_cookie(
                key='access_token', value=token['access_token'])
            response.set_cookie(
                key='refresh_token', value=token['refresh_token'])
            response.set_cookie(key='auth_req', value='')

            return response

        try:
            user = User.objects.get(Q(username=data.get('username')) |
                                    Q(email=data.get('email')))
            if user and not user.is_active:
                return Response({'errors': 'Account is disabled.'},
                                status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            pass

        return Response({'errors': error_msg},
                        status=status.HTTP_400_BAD_REQUEST)


class RegisterAPI(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        data = request.data.copy()

        serializer = RegisterSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        if data.get('email'):
            user, created = User.objects.get_or_create(email=data['email'])
            if not created:
                return Response({'errors': _('E-mail already exists.')},
                                status=status.HTTP_400_BAD_REQUEST)

            user.email = data['email']

        user.set_password(data['password'])
        user.is_active = True
        user.save()

        _get, created = Profile.objects.get_or_create(
            user=user, register_ip=str(get_client_ip(request)),)
        return Response({'msg': 'Successfully registered to the system.'}, status=status.HTTP_201_CREATED)


class ForgetPasswordAPI(APIView):
    """
    @brief      Class for Forget Password.
    """
    permission_classes = (AllowAny,)

    def post(self, request):
        data = request.data.copy()
        serializer = ForgetPasswordSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        if data.get('email'):
            try:
                user = User.objects.get(email=data['email'])
            except User.DoesNotExist:
                return Response({'errors': 'E-mail does not exist in the system'},
                                status=status.HTTP_400_BAD_REQUEST)

            if user and not user.is_active:
                return Response({'errors': 'E-mail does not exist in the system'},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            response = Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return response
        auth_token = AuthToken(user)
        token = auth_token.create_token()
        response = JsonResponse(
            {'data': {'reset_password_token': token['access_token']}},
            status=status.HTTP_200_OK)

        return response
