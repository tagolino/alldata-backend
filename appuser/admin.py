from django.contrib import admin

from .models import Profile


class ProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_username', 'is_active', 'is_online')

    def get_username(self, obj):
        if obj.user:
            return obj.user.username
        return ''
    get_username.short_description = 'username'

    def is_active(self, obj):
        if obj.user:
            return obj.user.is_active
        return False
    is_active.short_description = 'active'

admin.site.register(Profile, ProfileAdmin)
