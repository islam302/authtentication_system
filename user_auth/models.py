from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid
import secrets


class CustomUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.CharField(max_length=255, blank=True, null=True)

    ROLES = (
        ('admin', 'Admin'),
        ('user', 'User')
    )
    role = models.CharField(max_length=20, choices=ROLES, default='user')

    @property
    def is_admin_dynamic(self):
        return self.role == "admin"

    def __str__(self):
        return self.username


class APIKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=100, default='Default')
    key = models.CharField(max_length=64, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} — {self.user.username}"

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = f"nra_{secrets.token_hex(28)}"
        super().save(*args, **kwargs)

    @classmethod
    def create_for_user(cls, user, name='Default'):
        return cls.objects.create(user=user, name=name)
