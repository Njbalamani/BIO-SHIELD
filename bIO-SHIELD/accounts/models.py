from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Admin"
        REVIEWER = "REVIEWER", "Reviewer"
        ANALYST = "ANALYST", "Analyst"
        VIEWER = "VIEWER", "Viewer"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="users",
    )
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.VIEWER)

    def is_admin(self):
        return self.role == self.Role.ADMIN

    def is_reviewer(self):
        return self.role == self.Role.REVIEWER

    def is_analyst(self):
        return self.role == self.Role.ANALYST

    def is_viewer(self):
        return self.role == self.Role.VIEWER

    def __str__(self):
        return self.get_full_name() or self.username
