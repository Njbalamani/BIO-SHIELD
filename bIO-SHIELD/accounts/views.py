from django import forms
from django.contrib.auth import login
from django.contrib.auth.views import LoginView as DjangoLoginView
from django.contrib.auth.views import LogoutView as DjangoLogoutView
from django.urls import reverse_lazy
from django.views.generic import FormView

from accounts.models import User
from organizations.models import Organization


class RegistrationForm(forms.Form):
    username = forms.CharField(max_length=150)
    email = forms.EmailField(required=False)
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)
    organization = forms.ModelChoiceField(queryset=Organization.objects.all(), required=False)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password1") != cleaned.get("password2"):
            self.add_error("password2", "Passwords do not match.")
        return cleaned


class AccountLoginView(DjangoLoginView):
    template_name = "accounts/login.html"


class AccountLogoutView(DjangoLogoutView):
    next_page = reverse_lazy("accounts:login")


class RegisterView(FormView):
    form_class = RegistrationForm
    template_name = "accounts/register.html"
    success_url = reverse_lazy("dashboard:home")

    def form_valid(self, form):
        user = User.objects.create_user(
            username=form.cleaned_data["username"],
            email=form.cleaned_data.get("email") or "",
            password=form.cleaned_data["password1"],
            organization=form.cleaned_data.get("organization"),
            role=User.Role.VIEWER,
        )
        login(self.request, user)
        return super().form_valid(form)
