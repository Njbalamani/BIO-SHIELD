from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views import View
from django.views.generic import DetailView, FormView, ListView, TemplateView

from analysis.services import review_finding
from documents.models import (
    AccessAlert,
    AccessEvent,
    AnonymizationJob,
    DocumentVersion,
    HealthcareDocument,
    SensitiveDataFinding,
)
from documents.services import (
    create_document_from_upload,
    create_document_version,
    is_privileged,
    resolve_organization,
    user_organizations,
)
from documents.tasks import process_document_task
from documents.validators import validate_document_upload
from organizations.models import Organization
from organizations.services import organizations_for_user


def _organization_documents(user):
    organization_ids = list(organizations_for_user(user).values_list("pk", flat=True))
    return HealthcareDocument.objects.filter(organization_id__in=organization_ids)


class DocumentListView(LoginRequiredMixin, ListView):
    model = HealthcareDocument
    template_name = "documents/list.html"
    context_object_name = "documents"

    def get_queryset(self):
        return _organization_documents(self.request.user).select_related("organization")


class DocumentDetailView(LoginRequiredMixin, DetailView):
    model = HealthcareDocument
    template_name = "documents/detail.html"
    context_object_name = "document"

    def get_queryset(self):
        return _organization_documents(self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        document = self.object
        context["findings"] = SensitiveDataFinding.objects.filter(document=document)
        context["versions"] = DocumentVersion.objects.filter(document=document)
        context["access_events"] = AccessEvent.objects.filter(document=document)
        return context


class DocumentUploadForm(forms.Form):
    organization = forms.ModelChoiceField(queryset=Organization.objects.none())
    file = forms.FileField()
    title = forms.CharField(max_length=255, required=False)

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["organization"].queryset = organizations_for_user(user)


class DocumentUploadView(LoginRequiredMixin, FormView):
    form_class = DocumentUploadForm
    template_name = "documents/upload.html"
    success_url = reverse_lazy("documents:list")

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["organizations"] = organizations_for_user(self.request.user)
        return context

    def form_valid(self, form):
        upload = form.cleaned_data["file"]
        organization = resolve_organization(form.cleaned_data["organization"].pk, self.request.user)
        max_bytes = int(getattr(settings, "MAX_UPLOAD_SIZE_MB", 10)) * 1024 * 1024
        try:
            raw_bytes, extension, digest = validate_document_upload(upload, max_bytes)
        except ValueError as exc:
            form.add_error("file", str(exc))
            return self.form_invalid(form)
        upload.seek(0)
        document = create_document_from_upload(
            upload,
            organization,
            created_by=self.request.user,
            filename=upload.name,
            title=form.cleaned_data.get("title") or upload.name,
            is_synthetic=True,
        )
        create_document_version(document, raw_bytes, upload.name, self.request.user, note="Initial upload")
        process_document_task.delay(document.pk)
        self.object = document
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return reverse("documents:detail", kwargs={"pk": self.object.pk})


class FindingListView(LoginRequiredMixin, ListView):
    model = SensitiveDataFinding
    template_name = "findings/list.html"
    context_object_name = "findings"
    paginate_by = 25

    def get_queryset(self):
        organization_ids = list(organizations_for_user(self.request.user).values_list("pk", flat=True))
        return SensitiveDataFinding.objects.filter(organization_id__in=organization_ids).select_related("document")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["can_review_findings"] = is_privileged(self.request.user)
        return context


class FindingReviewView(LoginRequiredMixin, View):
    def post(self, request, pk, *args, **kwargs):
        organization_ids = [organization.pk for organization in user_organizations(request.user)]
        finding = get_object_or_404(
            SensitiveDataFinding.objects.select_related("document", "organization"),
            pk=pk,
            organization_id__in=organization_ids,
        )
        result = review_finding(finding, request.user, request.POST.get("status"), request=request, reveal=False)
        if result is None:
            raise PermissionDenied("Reviewer or admin role is required.")
        label = result["status"].replace("_", " ").lower()
        messages.success(request, f"Finding recorded as {label}.")
        return HttpResponseRedirect(reverse("findings:list"))


class AnonymizationJobListView(LoginRequiredMixin, ListView):
    model = AnonymizationJob
    template_name = "anonymization/list.html"
    context_object_name = "jobs"
    paginate_by = 25

    def get_queryset(self):
        organization_ids = list(organizations_for_user(self.request.user).values_list("pk", flat=True))
        return AnonymizationJob.objects.filter(organization_id__in=organization_ids).select_related("document")


class AccessListView(LoginRequiredMixin, TemplateView):
    template_name = "access/list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        organization_ids = list(organizations_for_user(self.request.user).values_list("pk", flat=True))
        context["events"] = AccessEvent.objects.filter(organization_id__in=organization_ids).select_related("document")[
            :100
        ]
        context["alerts"] = AccessAlert.objects.filter(organization_id__in=organization_ids).select_related("event")[
            :100
        ]
        return context
