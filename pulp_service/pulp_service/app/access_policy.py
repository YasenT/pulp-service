"""
Custom AccessPolicy for pulp-service that wraps upstream RBAC with
pulp-service-specific pre-checks (public domains, PyPI).

Use as DEFAULT_PERMISSION_CLASSES:
    REST_FRAMEWORK__DEFAULT_PERMISSION_CLASSES = [
        "pulp_service.app.access_policy.PulpServiceAccessPolicy"
    ]
"""

from rest_framework.permissions import SAFE_METHODS

from pulpcore.app.access_policy import AccessPolicyFromSettings


class PulpServiceAccessPolicy(AccessPolicyFromSettings):
    """
    AccessPolicy with pulp-service extensions:
      - Public domains (public-*): anonymous safe methods allowed
      - Delegates all other checks to standard RBAC (AccessPolicyFromSettings)

    PyPI views are already handled by their own DEFAULT_ACCESS_POLICY
    which uses "principal": "*" for read operations.
    """

    def has_permission(self, request, view):
        # Public domains: allow safe methods for everyone (including anonymous)
        if request.method in SAFE_METHODS:
            domain = getattr(request, "pulp_domain", None)
            if domain and "public-" in domain.name:
                return True

        return super().has_permission(request, view)

    def scope_queryset(self, view, qs):
        # On public domains, don't scope reads — show everything in the domain
        request = view.request
        if request.method in SAFE_METHODS:
            domain = getattr(request, "pulp_domain", None)
            if domain and "public-" in domain.name:
                return qs

        return super().scope_queryset(view, qs)
