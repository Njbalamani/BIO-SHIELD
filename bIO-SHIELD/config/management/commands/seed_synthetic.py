from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils.text import slugify

from accounts.models import User
from audit.services import audit
from compliance.services import build_checklist
from documents.models import HealthcareDocument
from documents.services import (
    build_synthetic_events,
    create_document_from_upload,
    create_document_version,
    process_document,
)
from organizations.models import Organization

INLINE_SAMPLES = (
    """BioShield Synthetic Sample 1

Patient Name: SYNTHETIC PATIENT ALPHA
MRN: SYN-MRN-0001
DOB: 2001-01-01
Email: synthetic.alpha@example.invalid
Phone: 555-0101
Diagnosis: SYNTHETIC CONDITION A
Medication: SYNTHETIC MEDICATION A
""",
    """BioShield Synthetic Sample 2

Patient Name: SYNTHETIC PATIENT BRAVO
MRN: SYN-MRN-0002
DOB: 2002-02-02
Email: synthetic.bravo@example.invalid
Phone: 555-0102
ICD-10: Z00.00
Diagnosis: SYNTHETIC CONDITION B
""",
    """BioShield Synthetic Sample 3

Patient Name: SYNTHETIC PATIENT CHARLIE
MRN: SYN-MRN-0003
DOB: 2003-03-03
Insurance ID: SYN-POLICY-0003
Email: synthetic.charlie@example.invalid
Phone: 555-0103
Medication: SYNTHETIC MEDICATION C
""",
)

ROLES = ("ADMIN", "REVIEWER", "ANALYST", "VIEWER")


def seed_synthetic_data(organizations=1, documents=3, events=20, organization=None, **kwargs):
    base_name = str(
        organization or kwargs.get("organization_name") or kwargs.get("name") or "BioShield Synthetic Organization"
    )
    organization_count = max(1, int(organizations))
    document_count = max(0, int(documents))
    event_count = max(0, int(events))
    results = []
    for index in range(organization_count):
        name = base_name if organization_count == 1 else f"{base_name} {index + 1}"
        results.append(_seed_one_organization(name, document_count, event_count))
    return results[0] if organization_count == 1 else results


@transaction.atomic
def _seed_one_organization(organization_name, document_count, event_count):
    organization_name = str(organization_name)
    organization, _ = Organization.objects.get_or_create(
        name=organization_name,
        defaults={
            "slug": slugify(organization_name)[:255],
            "description": "Synthetic demonstration data only; no real patient data.",
        },
    )
    users = {}
    for role in ROLES:
        username = f"synthetic_{role.lower()}_{organization.pk}"
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": f"{username}@example.invalid",
                "role": role,
                "organization": organization,
                "is_staff": role == "ADMIN",
            },
        )
        if created:
            user.set_password("SyntheticPass123!")
            user.save()
        else:
            user.organization = organization
            user.role = role
            user.save(update_fields=["organization", "role"])
        users[role] = user
    admin = users["ADMIN"]
    sample_dir = Path(settings.BASE_DIR) / "samples"
    sample_files = sorted(sample_dir.glob("*.txt"))[:document_count] if sample_dir.is_dir() else []
    documents = []
    for index in range(document_count):
        filename = f"synthetic_sample_{index + 1}.txt"
        sample_path = sample_files[index] if index < len(sample_files) else None
        if sample_path is not None:
            raw_bytes = sample_path.read_bytes()
        else:
            raw_bytes = INLINE_SAMPLES[index % len(INLINE_SAMPLES)].encode("utf-8")
        document = HealthcareDocument.objects.filter(
            organization=organization,
            original_filename=filename,
        ).first()
        if document is None:
            document = create_document_from_upload(
                raw_bytes,
                organization,
                created_by=admin,
                filename=filename,
                title=f"Synthetic sample document {index + 1}",
                is_synthetic=True,
            )
            create_document_version(document, raw_bytes, filename, admin, note="Synthetic seed version")
            process_document(document.pk)
        documents.append(document)
        build_synthetic_events(organization, document, count=event_count)
    checklist = build_checklist(organization, "HIPAA_SECURITY", created_by=admin)
    audit(
        admin,
        organization,
        "SYNTHETIC_SEED_COMPLETED",
        "Organization",
        str(organization.pk),
        {"documents": len(documents), "events": len(documents) * event_count},
        None,
    )
    return {
        "organization": organization,
        "documents": documents,
        "checklist": checklist,
        "events": len(documents) * event_count,
    }


class Command(BaseCommand):
    help = "Create synthetic-only organizations, users, documents, events, and checklists."

    def add_arguments(self, parser):
        parser.add_argument("--organization", default="BioShield Synthetic Organization")
        parser.add_argument("--organizations", type=int, default=1)
        parser.add_argument("--documents", type=int, default=3)
        parser.add_argument("--events", type=int, default=40)

    def handle(self, *args, **options):
        result = seed_synthetic_data(
            organizations=options["organizations"],
            documents=options["documents"],
            events=options["events"],
            organization=options["organization"],
        )
        if isinstance(result, list):
            organizations = [item["organization"] for item in result]
            document_count = sum(len(item["documents"]) for item in result)
            checklist_count = len(result)
        else:
            organizations = [result["organization"]]
            document_count = len(result["documents"])
            checklist_count = 1
        names = ", ".join(organization.name for organization in organizations)
        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded synthetic organization {names}: {document_count} documents, {checklist_count} checklist(s)."
            )
        )
