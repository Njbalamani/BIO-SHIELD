from django.urls import path

from accounts.views import AccountLoginView, AccountLogoutView, RegisterView

app_name = "accounts"

urlpatterns = [
    path("login/", AccountLoginView.as_view(), name="login"),
    path("register/", RegisterView.as_view(), name="register"),
    path("logout/", AccountLogoutView.as_view(), name="logout"),
]
