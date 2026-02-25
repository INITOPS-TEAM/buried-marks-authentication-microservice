from django.utils import timezone
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["username"] = user.username
        token["role"] = user.role
        token["inspector"] = user.is_inspector
        token["is_first_login"] = user.is_first_login
        token["authorized_for_date"] = timezone.now().date().isoformat()

        return token
