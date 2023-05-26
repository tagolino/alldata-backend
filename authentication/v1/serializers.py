from django.contrib.auth import password_validation
from django.contrib.auth.models import User
from django.core import exceptions
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers


class AuthenticationBaseSerializer(serializers.ModelSerializer):
    phone_regex = RegexValidator(regex=r'\d{4,30}$',
                                 message='Please register a valid '
                                         'phone number.')
    password = serializers.CharField(max_length=120,
                                     write_only=True,
                                     required=True,
                                     error_messages={'blank': 'Cannot be blank.'})

    class Meta:
        model = User
        fields = ('password',)

    def validate(self, attrs):
        password = attrs.get('password')

        errors = {}
        try:
            password_validation.validate_password(password=password,
                                                  user=User)
        except exceptions.ValidationError as e:
            errors['password'] = list(e.messages)
            errors['password'].append('Password should be 8-64 numbers, letters, symbols.')

        if errors:
            raise serializers.ValidationError(errors)

        return super().validate(attrs)


class UserLoginSerializer(AuthenticationBaseSerializer):
    phone_regex = RegexValidator(regex=r'\d{4,30}$',
                                 message={'blank': 'Cannot be blank.'})
    email = serializers.EmailField(required=False, write_only=True)

    class Meta:
        model = User
        fields = ('password', 'email')


class RegisterSerializer(AuthenticationBaseSerializer):
    phone_regex = RegexValidator(regex=r'\d{4,30}$',
                                 message={'blank': 'Cannot be blank.'})
    email = serializers.EmailField(required=False, write_only=True)

    class Meta:
        model = User
        fields = ('email',)


class ForgetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False, write_only=True)

    class Meta:
        model = User
        fields = ('email',)

    def validate(self, attrs):
        if not attrs.get('phone') and not attrs.get('email'):
            raise serializers.ValidationError({
                'email': _('Atleast one in phone or email input is required')
            })
        return super().validate(attrs)


class ResetPasswordSerializer(AuthenticationBaseSerializer):
    confirm_password = serializers.CharField(max_length=120,
                                             write_only=True,
                                             required=True,
                                             error_messages={'blank': 'Cannot be blank.'})

    class Meta:
        model = User
        fields = ('password', 'confirm_password')

    def validate(self, attrs):
        if not attrs.get('phone') and not attrs.get('email'):
            raise serializers.ValidationError({
                'email': _('Atleast one in phone or email input is required')
            })
        return super().validate(attrs)
