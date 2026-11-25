import uuid

from django.conf import settings


class BioShieldSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.META.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())
        request.META["X-Request-ID"] = request_id
        response = self.get_response(request)
        headers = {
            "X-Request-ID": request_id,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": getattr(settings, "SECURE_REFERRER_POLICY", "same-origin"),
            "Permissions-Policy": getattr(
                settings,
                "SECURE_PERMISSIONS_POLICY",
                "camera=(), microphone=(), geolocation=(), interest-cohort=()",
            ),
            "Cross-Origin-Opener-Policy": getattr(settings, "SECURE_CROSS_ORIGIN_OPENER_POLICY", "same-origin"),
            "Cross-Origin-Resource-Policy": getattr(settings, "SECURE_CROSS_ORIGIN_RESOURCE_POLICY", "same-origin"),
        }
        csp = getattr(settings, "CONTENT_SECURITY_POLICY", None)
        if csp:
            headers["Content-Security-Policy"] = csp
        for name, value in headers.items():
            if value and name not in response:
                response[name] = value
        return response
