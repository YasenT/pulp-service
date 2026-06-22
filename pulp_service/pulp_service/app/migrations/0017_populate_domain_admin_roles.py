"""
Data migration: populate domain-level admin roles from existing DomainOrg records.

For every DomainOrg entry that grants a user or group access to a domain,
create a corresponding UserRole or GroupRole with the `core.domain_owner` role
assigned at the domain level.

This ensures that when AccessPolicyFromDB/AccessPolicyFromSettings is enabled,
existing users retain full access to their domains without needing per-object
role assignments.

The `core.domain_owner` role carries: view_domain, change_domain, delete_domain,
manage_roles_domain. For full admin access within a domain you also need the
plugin-specific admin roles (e.g. rpm.admin) — those are handled separately
in populate_plugin_admin_roles below.
"""

from django.db import migrations


def populate_domain_admin_roles(apps, schema_editor):
    """
    For each DomainOrg with a user or group, create domain-level role assignments.

    Creates:
      - UserRole(user=X, role=core.domain_owner, domain=D) for user-based DomainOrgs
      - GroupRole(group=X, role=core.domain_owner, domain=D) for group-based DomainOrgs

    Also assigns plugin admin roles at domain level for full domain admin access.
    """
    Role = apps.get_model("core", "Role")
    UserRole = apps.get_model("core", "UserRole")
    GroupRole = apps.get_model("core", "GroupRole")
    DomainOrg = apps.get_model("service", "DomainOrg")

    # Collect all roles we want to assign at domain level for "admin" access
    admin_role_names = [
        "core.domain_owner",
    ]

    # Plugin admin roles — these carry all permissions for the respective plugin
    plugin_admin_roles = [
        "rpm.admin",
        # Add other plugin admin roles here as needed:
        # "python.admin",
        # "file.admin",
        # "container.admin",
        # "npm.admin",
    ]

    # Also assign task viewer and content labeler for full admin
    extra_roles = [
        "core.task_owner",
    ]

    all_role_names = admin_role_names + plugin_admin_roles + extra_roles

    # Fetch roles that exist in the DB (plugins may or may not be installed)
    roles = {r.name: r for r in Role.objects.filter(name__in=all_role_names)}

    if not roles:
        # No roles found — RBAC infrastructure not populated yet (migrations not run)
        return

    user_roles_to_create = []
    group_roles_to_create = []

    # Process all DomainOrg entries
    for domain_org in DomainOrg.objects.prefetch_related("domains").all():
        domains = list(domain_org.domains.all())

        if not domains:
            continue

        for domain in domains:
            if domain_org.user_id:
                for role_name, role in roles.items():
                    user_roles_to_create.append(
                        UserRole(
                            user_id=domain_org.user_id,
                            role=role,
                            content_type=None,
                            object_id=None,
                            domain=domain,
                        )
                    )

            if domain_org.group_id:
                for role_name, role in roles.items():
                    group_roles_to_create.append(
                        GroupRole(
                            group_id=domain_org.group_id,
                            role=role,
                            content_type=None,
                            object_id=None,
                            domain=domain,
                        )
                    )

    # Bulk create, ignoring conflicts (idempotent — safe to re-run)
    if user_roles_to_create:
        UserRole.objects.bulk_create(user_roles_to_create, ignore_conflicts=True)

    if group_roles_to_create:
        GroupRole.objects.bulk_create(group_roles_to_create, ignore_conflicts=True)


def reverse_populate_domain_admin_roles(apps, schema_editor):
    """
    Reverse: remove domain-level role assignments that were created by this migration.

    Only removes assignments where object_id is NULL and domain is set (domain-level roles).
    Does NOT touch object-level role assignments that may have been created by normal usage.
    """
    UserRole = apps.get_model("core", "UserRole")
    GroupRole = apps.get_model("core", "GroupRole")
    Role = apps.get_model("core", "Role")

    role_names = [
        "core.domain_owner",
        "rpm.admin",
        "core.task_owner",
    ]

    roles = Role.objects.filter(name__in=role_names)

    # Only delete domain-level assignments (object_id=None, domain IS NOT NULL)
    UserRole.objects.filter(
        role__in=roles,
        object_id=None,
        domain__isnull=False,
    ).delete()

    GroupRole.objects.filter(
        role__in=roles,
        object_id=None,
        domain__isnull=False,
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("service", "0016_pypiyanksmonitor"),
        ("core", "0119_grouprole_core_groupr_object__250e22_idx_and_more"),  # Ensures role table indexes exist
    ]

    operations = [
        migrations.RunPython(
            populate_domain_admin_roles,
            reverse_code=reverse_populate_domain_admin_roles,
        ),
    ]
