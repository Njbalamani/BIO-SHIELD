from django.urls import path

from analysis.views import AssessmentListView
from documents import views

app_name = "documents"

urlpatterns = [
    path("", views.DocumentListView.as_view(), name="list"),
    path("upload/", views.DocumentUploadView.as_view(), name="upload"),
    path("<int:pk>/", views.DocumentDetailView.as_view(), name="detail"),
]

finding_urlpatterns = [
    path("", views.FindingListView.as_view(), name="list"),
    path("<int:pk>/review/", views.FindingReviewView.as_view(), name="review"),
]

assessment_urlpatterns = [
    path("", AssessmentListView.as_view(), name="list"),
]

anonymization_urlpatterns = [
    path("", views.AnonymizationJobListView.as_view(), name="list"),
]

access_urlpatterns = [
    path("", views.AccessListView.as_view(), name="list"),
]
