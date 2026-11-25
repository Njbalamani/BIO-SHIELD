from django.urls import path

from reports.views import ReportListView

app_name = "reports"

urlpatterns = [
    path("", ReportListView.as_view(), name="list"),
]
