from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, APIKey


class APIKeyInline(admin.TabularInline):
    model = APIKey
    extra = 0
    readonly_fields = ('id', 'key', 'created_at')
    fields = ('id', 'name', 'key', 'is_active', 'created_at')


class CustomUserAdmin(UserAdmin):
    list_display = ('id', 'username', 'email', 'role', 'is_staff')
    inlines = [APIKeyInline]
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('email', 'organization')}),
        ('Permissions', {'fields': ('role', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )


admin.site.register(CustomUser, CustomUserAdmin)
