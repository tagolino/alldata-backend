from rest_framework import serializers

from ..models import Profile


class UserProfileSerializer(serializers.ModelSerializer):
    error_messages = {
        'blank': 'This field is required.'
    }
    payment_password = serializers.CharField(write_only=True, required=True,
                                             error_messages=error_messages)
    nickname = serializers.CharField(min_length=2, max_length=12,
                                     required=True)
    email = serializers.EmailField(required=False, write_only=True)

    class Meta:
        model = Profile
        fields = ('id', 'first_name', 'middle_name', 'last_name')

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if instance.user:
            email = instance.user.email
            ret['user'] = {
                'real_email': email
            }

            if instance.user.username == instance.user.email:
                ret['user']['username'] = ret['user']['email']
        return ret
