from django.contrib.auth import authenticate
from django.core.exceptions import FieldDoesNotExist
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import User
from accounts.serializers import UserCreateSerializer, UserSerializer
from organizations.services import organizations_for_user, user_can_view_org


def has_field(model, name):
    current = model
    parts = str(name).split("__")
    for index, part in enumerate(parts):
        try:
            field = current._meta.get_field(part)
        except (FieldDoesNotExist, AttributeError):
            return False
        if index == len(parts) - 1:
            return True
        current = getattr(field, "related_model", None)
        if current is None:
            return False
    return False


def scoped_queryset(queryset, request, field="organization"):
    user = request.user
    if not user or not getattr(user, "is_authenticated", False):
        return queryset.none()
    if getattr(user, "is_superuser", False) or str(getattr(user, "role", "")).upper() == "ADMIN":
        return queryset
    if not has_field(queryset.model, field):
        return queryset.none()
    organization_ids = list(organizations_for_user(user).values_list("pk", flat=True))
    return queryset.filter(**{f"{field}__id__in": organization_ids})


class IsOrganizationMember(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        organization = getattr(obj, "organization", None)
        if organization is None:
            return True
        return user_can_view_org(request.user, organization)


class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        payload = dict(request.data or {})
        role = str(payload.pop("role", "") or "VIEWER").upper()
        privileged = getattr(request.user, "is_authenticated", False) and (
            getattr(request.user, "is_superuser", False) or str(getattr(request.user, "role", "")).upper() == "ADMIN"
        )
        if not privileged:
            role = "VIEWER"
        if role not in User.Role.values:
            role = "VIEWER"
        if not payload.get("organization") and payload.pop("organization_id", None):
            payload["organization"] = request.data.get("organization_id")
        payload["role"] = role
        serializer = UserCreateSerializer(data=payload)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            {"token": token.key, "user": UserSerializer(user, context={"request": request}).data},
            status=status.HTTP_201_CREATED,
        )


class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        username = request.data.get("username") or ""
        password = request.data.get("password") or ""
        email = request.data.get("email") or ""
        if not username and email:
            user = User.objects.filter(email__iexact=email).first()
            username = getattr(user, "username", "") or email
        user = authenticate(request, username=username, password=password)
        if user is None or not user.is_active:
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key, "user": UserSerializer(user, context={"request": request}).data})


class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        Token.objects.filter(user=request.user).delete()
        return Response({"detail": "Logged out."})


class MeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user, context={"request": request}).data)
