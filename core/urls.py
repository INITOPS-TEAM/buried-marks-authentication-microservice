from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from users.views import Step1LoginView, Step2LoginView, ActiveUserEmailsView, \
    EligibleUsersCountView, \
    BanUserView, UpdateUserRoleView, InviteUserView, AcceptInviteView, UserListView, ArchitectEmailView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/login/step1/", Step1LoginView.as_view(), name="login_step1"),
    path("api/login/step2/", Step2LoginView.as_view(), name="login_step2"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path('api/emails/', ActiveUserEmailsView.as_view(), name='internal_emails'),
    path('api/users/count/', EligibleUsersCountView.as_view(), name='users-count'),
    path('api/users/<int:user_id>/ban/', BanUserView.as_view(), name='user-ban'),
    path('api/users/<int:user_id>/role/', UpdateUserRoleView.as_view(), name='user-role-update'),
    path('api/users/', UserListView.as_view(), name='user_list'),
    path('invite/', InviteUserView.as_view(), name='invite_user'),
    path('accept-invite/', AcceptInviteView.as_view(), name='accept_invite'),
    path('architect/send-email/', ArchitectEmailView.as_view(), name='architect_send_email'),
]
