import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

from user_auth.models import CustomUser


# Fixtures

@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def superuser(db):
    return CustomUser.objects.create_superuser(
        username="admin",
        email="admin@example.com",
        password="AdminPass123!",
    )


@pytest.fixture
def normal_user(db):
    return CustomUser.objects.create_user(
        username="testuser",
        email="testuser@example.com",
        password="UserPass123!",
    )


@pytest.fixture
def auth_client(superuser):
    client = APIClient()
    refresh = RefreshToken.for_user(superuser)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client


@pytest.fixture
def user_client(normal_user):
    client = APIClient()
    refresh = RefreshToken.for_user(normal_user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client


# Authentication

@pytest.mark.django_db
def test_register(api_client):
    url = reverse("register")
    data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "NewPass123!",
        "password_confirm": "NewPass123!",
    }
    response = api_client.post(url, data)
    assert response.status_code == 201
    assert "api_key" in response.data
    assert response.data["api_key"].startswith("nra_")


@pytest.mark.django_db
def test_register_password_mismatch(api_client):
    url = reverse("register")
    data = {
        "username": "newuser2",
        "email": "newuser2@example.com",
        "password": "NewPass123!",
        "password_confirm": "WrongPass!",
    }
    response = api_client.post(url, data)
    assert response.status_code == 400


@pytest.mark.django_db
def test_token_obtain_pair(api_client, normal_user):
    url = reverse("token_obtain_pair")
    response = api_client.post(url, {"username": "testuser", "password": "UserPass123!"})
    assert response.status_code == 200
    assert "access" in response.data
    assert "refresh" in response.data
    assert "username" in response.data
    assert "role" in response.data


@pytest.mark.django_db
def test_token_wrong_credentials(api_client):
    url = reverse("token_obtain_pair")
    response = api_client.post(url, {"username": "nobody", "password": "wrong"})
    assert response.status_code == 401


@pytest.mark.django_db
def test_token_refresh(api_client, normal_user):
    refresh = RefreshToken.for_user(normal_user)
    url = reverse("token_refresh")
    response = api_client.post(url, {"refresh": str(refresh)})
    assert response.status_code == 200
    assert "access" in response.data


@pytest.mark.django_db
def test_logout(user_client, normal_user):
    refresh = RefreshToken.for_user(normal_user)
    url = reverse("logout")
    response = user_client.post(url, {"refresh": str(refresh)})
    assert response.status_code == 200


@pytest.mark.django_db
def test_logout_requires_auth(api_client, normal_user):
    refresh = RefreshToken.for_user(normal_user)
    url = reverse("logout")
    response = api_client.post(url, {"refresh": str(refresh)})
    assert response.status_code == 401


# Profile

@pytest.mark.django_db
def test_get_profile(user_client, normal_user):
    url = reverse("user_profile")
    response = user_client.get(url)
    assert response.status_code == 200
    assert response.data["username"] == normal_user.username
    assert "has_api_key" in response.data


@pytest.mark.django_db
def test_update_profile(user_client):
    url = reverse("user_profile")
    response = user_client.patch(url, {"organization": "ACME Corp"})
    assert response.status_code == 200
    assert response.data["organization"] == "ACME Corp"


@pytest.mark.django_db
def test_profile_requires_auth(api_client):
    url = reverse("user_profile")
    response = api_client.get(url)
    assert response.status_code == 401


# API Key

@pytest.mark.django_db
def test_get_api_key(user_client, normal_user):
    normal_user.generate_api_key()
    url = reverse("api_key")
    response = user_client.get(url)
    assert response.status_code == 200
    assert "api_key" in response.data


@pytest.mark.django_db
def test_generate_api_key(user_client):
    url = reverse("api_key")
    response = user_client.post(url)
    assert response.status_code == 201
    assert response.data["api_key"].startswith("nra_")


@pytest.mark.django_db
def test_revoke_api_key(user_client, normal_user):
    normal_user.generate_api_key()
    url = reverse("api_key")
    response = user_client.delete(url)
    assert response.status_code == 200
    normal_user.refresh_from_db()
    assert normal_user.api_key is None


@pytest.mark.django_db
def test_api_key_authentication(api_client, normal_user):
    normal_user.generate_api_key()
    api_client.credentials(**{"HTTP_X_API_KEY": normal_user.api_key})
    url = reverse("user_profile")
    response = api_client.get(url)
    assert response.status_code == 200


# Admin User Management

@pytest.mark.django_db
def test_user_list_superuser(auth_client):
    url = reverse("user-list")
    response = auth_client.get(url)
    assert response.status_code == 200


@pytest.mark.django_db
def test_user_list_forbidden_for_normal_user(user_client):
    url = reverse("user-list")
    response = user_client.get(url)
    assert response.status_code == 403


@pytest.mark.django_db
def test_user_create_superuser(auth_client):
    url = reverse("user-list")
    data = {
        "username": "managed_user",
        "email": "managed@example.com",
        "password": "Managed123!",
        "role": "user",
    }
    response = auth_client.post(url, data)
    assert response.status_code in [200, 201]


@pytest.mark.django_db
def test_user_update_superuser(auth_client, normal_user):
    url = reverse("user-detail", args=[str(normal_user.id)])
    response = auth_client.patch(url, {"organization": "Updated Org"})
    assert response.status_code == 200
    assert response.data["organization"] == "Updated Org"


@pytest.mark.django_db
def test_user_delete_superuser(auth_client, normal_user):
    url = reverse("user-detail", args=[str(normal_user.id)])
    response = auth_client.delete(url)
    assert response.status_code == 204


# Password Reset

@pytest.mark.django_db
def test_password_reset_request_unknown_email(api_client):
    url = reverse("password_reset")
    response = api_client.post(url, {"email": "nobody@example.com"})
    assert response.status_code == 404


@pytest.mark.django_db
def test_password_reset_confirm(api_client, normal_user):
    token = default_token_generator.make_token(normal_user)
    uidb64 = urlsafe_base64_encode(force_bytes(normal_user.pk))
    url = reverse("password_reset_confirm_api", kwargs={"uidb64": uidb64, "token": token})
    response = api_client.post(url, {"password": "NewSecure456!"})
    assert response.status_code == 200


@pytest.mark.django_db
def test_password_reset_confirm_invalid_token(api_client, normal_user):
    uidb64 = urlsafe_base64_encode(force_bytes(normal_user.pk))
    url = reverse("password_reset_confirm_api", kwargs={"uidb64": uidb64, "token": "bad-token"})
    response = api_client.post(url, {"password": "NewSecure456!"})
    assert response.status_code == 400
