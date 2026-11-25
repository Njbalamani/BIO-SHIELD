from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class BioShieldUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (("BioShield", {"fields": ("organization", "role")}),)
    list_display = ("username", "email", "organization", "role", "is_staff")
    list_filter = ("role", "organization", "is_staff")
