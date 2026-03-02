from django.contrib.auth import authenticate, get_user_model
from django.core import signing
from django.core.signing import BadSignature, SignatureExpired
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated, BasePermission
from rest_framework.response import Response
from rest_framework.views import APIView
import os
import valkey

from core import settings
from .models import CustomUser
from .serializers import CustomTokenObtainPairSerializer

User = get_user_model()


# login and password check, temp_login_token generation
class Step1LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response(
                {"error": "Please provide both username and password"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(username=username, password=password)

        if user is not None:
            signer = signing.TimestampSigner()
            temp_token = signer.sign_object({"user_id": user.id})

            return Response(
                {"temp_login_token": temp_token, "message": "Credentials valid"},
                status=status.HTTP_200_OK,
            )

        return Response(
                {"error": "Invalid username or password"},
                status=status.HTTP_401_UNAUTHORIZED,
            )


# Daily code check, access and refresh token generation
class Step2LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        temp_token = request.data.get("temp_login_token")
        daily_code = request.data.get("daily_code")

        if not temp_token or not daily_code:
            return Response(
                {"error": "Both temp_login_token and daily_code are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Decrypt token
        signer = signing.TimestampSigner()
        try:
            # Token alive for 5 min
            unsigned_data = signer.unsign_object(temp_token, max_age=300)
            user_id = unsigned_data.get("user_id")
        except SignatureExpired:
            return Response(
                {"error": "Temporary token expired. Please login again"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except BadSignature:
            return Response(
                {"error": "Invalid temporary token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # REQUEST TO DAILY_CODE SERVICE
        valkey_addr = os.environ.get("VALKEY_ADDR")

        try:
            r = valkey.from_url(f"valkey://{valkey_addr}/0", decode_responses=True)

            actual_daily_code = r.get("daily_code:global")

            if daily_code != actual_daily_code:
                return Response(
                    {"error": "Invalid daily code."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        except valkey.ValkeyError as e:
            return Response(
                {"error": "Internal service error."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )

        # Generate JWT token
        refresh = CustomTokenObtainPairSerializer.get_token(user)

        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
            },
            status=status.HTTP_200_OK,
        )

class IsInternalService(BasePermission):
    def has_permission(self, request, view):
        secret_key = request.headers.get('X-Internal-Token')
        return secret_key == settings.SECRET_KEY

class ActiveUserEmailsView(APIView):
    permission_classes = [IsInternalService]

    def get(self, request):
        emails = list(CustomUser.objects.filter(is_active=True).values_list('email', flat=True))
        return Response({"emails": emails}, status=status.HTTP_200_OK)


class EligibleUsersCountView(APIView):
    permission_classes = [IsInternalService]

    def get(self, request):
        count = CustomUser.objects.filter(is_active=True).count()
        return Response({"total_eligible": count}, status=status.HTTP_200_OK)


class BanUserView(APIView):
    permission_classes = [IsInternalService]

    def post(self, request, user_id):
        user = get_object_or_404(CustomUser, id=user_id)

        if not user.is_active:
            return Response({"message": f"User {user_id} is already banned."}, status=status.HTTP_200_OK)

        user.is_active = False
        user.save()

        return Response({"message": f"User {user_id} successfully banned."}, status=status.HTTP_200_OK)


class UpdateUserRoleView(APIView):
    permission_classes = [IsInternalService]

    def patch(self, request, user_id):
        user = get_object_or_404(CustomUser, id=user_id)
        new_role = request.data.get("role")

        if not new_role:
            return Response({"error": "Field role is required."}, status=status.HTTP_400_BAD_REQUEST)

        user.role = new_role
        user.save()

        return Response({"message": f"User {user_id} role updated to '{new_role}'."}, status=status.HTTP_200_OK)

# First login password change
class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        new_password = request.data.get("new_password")

        if not new_password:
            return Response(
                {"error": "Please provide a new_password"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user

        user.set_password(new_password)
        user.is_first_login = False
        user.save()

        return Response(
            {"message": "Password updated successfully"}, status=status.HTTP_200_OK
        )

