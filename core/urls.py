from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from users.views import Step1LoginView, Step2LoginView, UpdatePasswordView, ActiveUserEmailsView, EligibleUsersCountView, \
    BanUserView, UpdateUserRoleView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/login/step1/", Step1LoginView.as_view(), name="login_step1"),
    path("api/login/step2/", Step2LoginView.as_view(), name="login_step2"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/update-password/", UpdatePasswordView.as_view(), name="update_password"),
    path('api/emails/', ActiveUserEmailsView.as_view(), name='internal_emails'),
    path('api/users/count/', EligibleUsersCountView.as_view(), name='users-count'),
    path('api/users/<int:user_id>/ban/', BanUserView.as_view(), name='user-ban'),
    path('api/users/<int:user_id>/role/', UpdateUserRoleView.as_view(), name='user-role-update'),
]
