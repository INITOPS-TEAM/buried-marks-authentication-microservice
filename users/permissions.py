from rest_framework.permissions import BasePermission
from django.conf import settings

class IsInternalService(BasePermission):
    def has_permission(self, request, view):
        secret_key = request.headers.get('X-Internal-Token')
        return secret_key == settings.SECRET_KEY

class IsGoldUserOrArchitect(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            str(request.user.role) in ['3', '4']
        )

class IsInspectorOrArchitect(BasePermission):
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        return request.user.is_inspector or str(request.user.role) == '4'

class IsArchitectOnly(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            str(request.user.role) == '4'
        )