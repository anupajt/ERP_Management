from django.urls import path
from rest_framework_simplejwt.views import (TokenObtainPairView, TokenRefreshView)
from .views import (RegisterView, LogoutView, ProfileView, home_view, login_view, logout_view, register_view,user_list_view,
                    profile_view, edit_user_view,edit_user_view, delete_user_view, view_user_view, accounts_login_redirect)

urlpatterns = [
    # API endpoints
    path('api/register/', RegisterView.as_view(), name='auth_register'),
    path('api/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/logout/', LogoutView.as_view(), name='auth_logout'),
    path('api/profile/', ProfileView.as_view(), name='user_profile'),
    
    # Frontend views
    path('', home_view, name='home'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('register/', register_view, name='register'),
    path('users/', user_list_view, name='user_list'),
    path('profile/', profile_view, name='profile'),
    path('profile/edit/', edit_user_view, name='edit_profile'),
    path('users/<int:user_id>/edit/', edit_user_view, name='edit_user'),
    path('users/<int:user_id>/delete/', delete_user_view, name='delete_user'),
    path('users/<int:user_id>/', view_user_view, name='view_user'),
    path('accounts/login/', accounts_login_redirect),
]