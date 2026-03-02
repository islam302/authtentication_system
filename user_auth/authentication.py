from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import APIKey


class APIKeyAuthentication(BaseAuthentication):
    """
    Custom authentication using API key in header.

    Usage:
        Header: X-API-Key: nra_xxxxxxxxxxxx
    """
    keyword = 'X-API-Key'

    def authenticate(self, request):
        api_key = request.headers.get(self.keyword)

        if not api_key:
            return None

        try:
            key_obj = APIKey.objects.select_related('user').get(
                key=api_key, is_active=True, user__is_active=True
            )
        except APIKey.DoesNotExist:
            raise AuthenticationFailed('Invalid API key')

        return (key_obj.user, key_obj)

    def authenticate_header(self, request):
        return self.keyword
