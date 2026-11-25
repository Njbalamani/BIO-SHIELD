from django.urls import path

from compliance.views import ChecklistListView

app_name = "compliance"

urlpatterns = [
    path("", ChecklistListView.as_view(), name="list"),
]
