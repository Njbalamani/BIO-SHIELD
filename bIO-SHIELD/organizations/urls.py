from django.urls import path

from organizations.views import OrganizationListView

app_name = "organizations"

urlpatterns = [
    path("", OrganizationListView.as_view(), name="list"),
]
