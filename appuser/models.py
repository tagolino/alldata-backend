from django.contrib.auth.models import User
from django.db import models


class Profile(models.Model):
    ROLE_MEMBER = 'member'
    ROLE_SUPERADMIN = 'superadmin'
    ROLE_ADMIN = 'admin'
    ROLE_OPTIONS = (
        (ROLE_MEMBER, 'Member'),
        (ROLE_ADMIN, 'Admin'),
        (ROLE_SUPERADMIN, 'Superadmin')
    )
    
    user = models.OneToOneField(User,
                                null=True,
                                blank=True,
                                related_name='profile',
                                on_delete=models.SET_NULL)
    first_name = models.CharField(max_length=125, null=True, blank=True)
    middle_name = models.CharField(max_length=125, null=True, blank=True)
    last_name = models.CharField(max_length=125, null=True, blank=True)
    birthday = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User,
                                   null=True,
                                   blank=True,
                                   related_name='profiles_created',
                                   on_delete=models.SET_NULL)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User,
                                   null=True,
                                   blank=True,
                                   related_name='profiles_updated',
                                   on_delete=models.SET_NULL)
    last_login_at = models.DateTimeField(auto_now=True)
    role = models.CharField(default=ROLE_MEMBER, choices=ROLE_OPTIONS,
                            max_length=255)
    login_ip = models.CharField(max_length=128, null=True, blank=True)
    register_ip = models.CharField(max_length=128, null=True, blank=True)
    
    def __str__(self):
        if self.user:
            return self.user.username
        return str(self.id)
