from django.core.exceptions import PermissionDenied
from django.http import Http404

from .models import Organization


def organizations_for_user(user):
    if not user or not getattr(user, "is_authenticated", False):
        return Organization.objects.none()
    if user.is_superuser or user.is_admin():
        return Organization.objects.all()
    if user.organization_id:
        return Organization.objects.filter(pk=user.organization_id)
    return Organization.objects.none()


def organization_for_user(user, org_id):
    organization = organizations_for_user(user).filter(pk=org_id).first()
    if organization is None:
        if not Organization.objects.filter(pk=org_id).exists():
            raise Http404("Organization not found")
        raise PermissionDenied("You do not have access to this organization")
    return organization


def user_can_view_org(user, organization):
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser or user.is_admin():
        return True
    return bool(user.organization_id and user.organization_id == organization.pk)


def require_role(user, *roles):
    if not user or not getattr(user, "is_authenticated", False):
        raise PermissionDenied("Authentication required")
    if user.is_superuser:
        return True
    if roles and user.role not in roles:
        raise PermissionDenied("Insufficient role")
    return True
