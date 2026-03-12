import secrets
from django.utils import timezone
from os import access

from django.contrib.auth import authenticate, get_user_model
from django.core import signing
from django.core.signing import BadSignature, SignatureExpired
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
import os
import valkey
import requests
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from .models import CustomUser
from .serializers import UserListSerializer, CustomTokenRefreshSerializer
from .permissions import IsInternalService, IsGoldUserOrArchitect, IsInspectorOrArchitect, IsArchitectOnly

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

            key_name = os.environ.get("DAILY_CODE_KEY")

            actual_daily_code = r.get(key_name)

            if daily_code.strip() != actual_daily_code.strip():
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
        refresh = RefreshToken.for_user(user)

        access_token = refresh.access_token
        access_token["username"] = user.username
        access_token["role"] = user.role
        access_token["inspector"] = user.is_inspector
        access_token["authorized_for_date"] = timezone.now().date().isoformat()

        return Response(
            {
                "access": str(access_token),
                "refresh": str(refresh),
            },
            status=status.HTTP_200_OK,
        )

class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer

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

class UserListView(ListAPIView):
    serializer_class = UserListSerializer
    permission_classes = [IsInspectorOrArchitect]

    def get_queryset(self):
        queryset = CustomUser.objects.filter(is_active=True)

        roles_param = self.request.query_params.get('roles')

        if roles_param:
            roles_list = roles_param.split(',')
            queryset = queryset.filter(role__in=roles_list)

        return queryset

class InviteUserView(APIView):
    permission_classes = [IsGoldUserOrArchitect]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response(
                {"error": "Fill in the email field"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(email=email).exists():
            return Response(
                {"error": "A user with this email address is already registered"},
                status=status.HTTP_400_BAD_REQUEST
            )

        token = secrets.token_urlsafe(32)

        valkey_addr = os.environ.get("VALKEY_ADDR")

        try:
            r = valkey.from_url(f"valkey://{valkey_addr}/0", decode_responses=True)
            cache_key = f"invite_token:{token}"
            ttl_time = 86400

            r.setex(cache_key, ttl_time, email)

        except valkey.ValkeyError as e:
            return Response(
                {"error": "DB error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        frontend_url = os.environ.get("FRONTEND_URL")
        invite_link = f"{frontend_url}/register?token={token}"

        mail_service_url = os.environ.get("MAIL_SERVICE_URL")
        endpoint = f"{mail_service_url}/api/send-invite"

        payload = {
            "email": email,
            "invite_link": invite_link
        }

        try:
            go_response = requests.post(endpoint, json=payload, timeout=5)
            go_response.raise_for_status()

        except requests.exceptions.RequestException as e:
            r.delete(cache_key)

            return Response(
                {"error": "Failed to send invitation letter. Please try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"message": f"Invitation successfully sent to {email}"},
            status=status.HTTP_201_CREATED
        )


class AcceptInviteView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get("token")
        username = request.data.get("username")
        password = request.data.get("password")

        if not token or not username or not password:
            return Response(
                {"error": "All fields are required "},
                status=status.HTTP_400_BAD_REQUEST
            )

        cache_key = f"invite_token:{token}"
        valkey_addr = os.environ.get("VALKEY_ADDR")

        try:
            r = valkey.from_url(f"valkey://{valkey_addr}/0", decode_responses=True)
            email = r.get(cache_key)
        except valkey.ValkeyError as e:
            return Response(
                {"error": "Valkey DB error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        if not email:
            return Response(
                {"error": "Invalid or expired registration link"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(username=username).exists():
            return Response(
                {"error": "A user with this username already exists"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(email=email).exists():
            r.delete(cache_key)
            return Response(
                {"error": "A user with this email address is already registered"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_active=True
        )

        try:
            r.delete(cache_key)
        except valkey.ValkeyError:
            pass

        return Response(
            {"message": f"Registration successful {username}."},
            status=status.HTTP_201_CREATED
        )

class ArchitectEmailView(APIView):
    permission_classes = [IsArchitectOnly]

    def post(self, request):
        roles = request.data.get("roles", [])
        subject = request.data.get("subject")
        custom_text = request.data.get("custom_text")

        if not roles or not isinstance(roles, list):
            return Response({"error": "Needed list of roles."}, status=status.HTTP_400_BAD_REQUEST)
        if not subject or not custom_text:
            return Response({"error": "Fill in the required fields"}, status=status.HTTP_400_BAD_REQUEST)

        valid_roles = {'1', '2', '3'}
        if not set(roles).issubset(valid_roles):
            return Response({"error": "Invalid roles specified. Allowed: 1, 2, 3."}, status=status.HTTP_400_BAD_REQUEST)

        target_emails = list(CustomUser.objects.filter(role__in=roles, is_active=True).values_list('email', flat=True))

        if not target_emails:
            return Response({"error": "No users with these roles were found."}, status=status.HTTP_404_NOT_FOUND)

        mail_service_url = os.environ.get("MAIL_SERVICE_URL")
        endpoint = f"{mail_service_url}/api/send-architect-email"

        payload = {
            "emails": target_emails,
            "subject": subject,
            "custom_text": custom_text
        }

        try:
            go_response = requests.post(endpoint, json=payload, timeout=10)
            go_response.raise_for_status()
        except requests.exceptions.RequestException:
            return Response(
                {"error": "Unable to reach mail service. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"message": f"The mailing has been successfully launched for {len(target_emails)} users."},
            status=status.HTTP_200_OK
        )

# First login password change
# class UpdatePasswordView(APIView):
#     permission_classes = [IsAuthenticated]
#
#     def post(self, request):
#         new_password = request.data.get("new_password")
#
#         if not new_password:
#             return Response(
#                 {"error": "Please provide a new_password"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#
#         user = request.user
#
#         user.set_password(new_password)
#         user.is_first_login = False
#         user.save()
#
#         return Response(
#             {"message": "Password updated successfully"}, status=status.HTTP_200_OK
#         )
