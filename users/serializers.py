from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import CustomUser

User = get_user_model()

class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = RefreshToken(attrs['refresh'])
        user_id = refresh['user_id']
        user = User.objects.get(id=user_id)

        access_token = refresh.access_token
        access_token['username'] = user.username
        access_token['role'] = user.role
        access_token['inspector'] = user.is_inspector
        access_token['authorized_for_date'] = timezone.now().date().isoformat()
        data['access'] = str(access_token)
        return data

class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'role']
