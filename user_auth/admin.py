from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser


class CustomUserAdmin(UserAdmin):
    list_display = ('id', 'username', 'email', 'role', 'is_staff')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('email', 'organization')}),
        ('Permissions', {'fields': ('role', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('API Key', {'fields': ('api_key', 'api_key_created_at')}),
    )
    readonly_fields = ('api_key', 'api_key_created_at')


admin.site.register(CustomUser, CustomUserAdmin)
