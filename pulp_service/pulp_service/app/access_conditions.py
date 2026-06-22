"""
Custom access policy conditions for pulp-service.

These are registered via DRF_ACCESS_POLICY['reusable_conditions'] in settings
and can be used in access policy statements like:

    {"action": ["list"], "principal": "*", "effect": "allow", "condition": "is_public_domain"}

Add to settings:
    DRF_ACCESS_POLICY = {
        "reusable_conditions": [
            "pulpcore.app.global_access_conditions",
            "pulp_service.app.access_conditions",
        ]
    }
"""


def is_public_domain(request, view, action):
    """
    Returns True if the request targets a public domain (name contains 'public-').

    Use this condition to allow anonymous/unauthenticated read access on public domains,
    replicating the current DomainBasedPermission behavior.

    Example policy statement:
        {
            "action": ["list", "retrieve"],
            "principal": "*",
            "effect": "allow",
            "condition": "is_public_domain",
        }
    """
    domain = getattr(request, "pulp_domain", None)
    return domain is not None and "public-" in domain.name


def is_public_domain_safe_method(request, view, action):
    """
    Returns True if the request is a safe method (GET/HEAD/OPTIONS) targeting a public domain.

    More restrictive than is_public_domain — only allows reads, not writes.

    Example policy statement:
        {
            "action": "*",
            "principal": "*",
            "effect": "allow",
            "condition": "is_public_domain_safe_method",
        }
    """
    from rest_framework.permissions import SAFE_METHODS

    if request.method not in SAFE_METHODS:
        return False
    domain = getattr(request, "pulp_domain", None)
    return domain is not None and "public-" in domain.name


def has_domain_org_access(request, view, action):
    """
    Returns True if the user has DomainOrg-based access to the current domain.

    This bridges the legacy DomainOrg model into RBAC conditions, allowing
    a transitional period where both systems can coexist.

    Example policy statement:
        {
            "action": ["list", "retrieve"],
            "principal": "authenticated",
            "effect": "allow",
            "condition": "has_domain_org_access",
        }
    """
    import json
    from base64 import b64decode

    from django.db.models import Q

    from pulpcore.plugin.util import get_domain_pk

    from pulp_service.app.models import DomainOrg

    user = request.user
    if not user.is_authenticated:
        return False

    domain_pk = get_domain_pk()

    # Build query matching the current DomainBasedPermission logic
    query = Q(domains__pk=domain_pk, user=user)

    group_pks = list(user.groups.values_list("pk", flat=True))
    if group_pks:
        query |= Q(domains__pk=domain_pk, group_id__in=group_pks)

    # Extract org_id from X-RH-IDENTITY header
    header_content = request.META.get("HTTP_X_RH_IDENTITY")
    if header_content:
        try:
            import jq

            decoded = json.loads(b64decode(header_content))
            org_id_path = jq.compile(".identity.internal.org_id")
            org_id = org_id_path.input_value(decoded).first()
            if org_id:
                query |= Q(domains__pk=domain_pk, org_id=org_id)
        except Exception:
            pass

    return DomainOrg.objects.filter(query).exists()
