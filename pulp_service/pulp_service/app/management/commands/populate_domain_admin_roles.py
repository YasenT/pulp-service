"""
Management command to populate domain-level admin roles from existing DomainOrg records.

Usage:
    pulpcore-manager populate_domain_admin_roles              # execute
    pulpcore-manager populate_domain_admin_roles --dry-run    # preview only
    pulpcore-manager populate_domain_admin_roles --domain=mydom  # single domain
    pulpcore-manager populate_domain_admin_roles --reverse    # remove created assignments

For every DomainOrg entry (user or group with access to a domain), this creates
domain-level role assignments so that RBAC (AccessPolicyFromDB/Settings) grants
the same full access that DomainBasedPermission provides today.

With a domain-level admin role, per-object permissions are NOT needed — the role
check short-circuits at domain level and returns access to all objects in that domain.
"""

from django.core.management.base import BaseCommand

from pulpcore.app.models import Domain
from pulpcore.app.models.role import GroupRole, Role, UserRole

from pulp_service.app.models import DomainOrg


# Roles to assign at domain level for full admin access
ADMIN_ROLE_NAMES = [
    "core.domain_owner",  # manage the domain itself
    "rpm.admin",  # full RPM plugin access
    # Uncomment as plugins are installed:
    # "python.admin",
    # "file.admin",
    # "container.admin",
    # "npm.admin",
]


class Command(BaseCommand):
    help = "Populate domain-level admin roles from existing DomainOrg records"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be created without making changes",
        )
        parser.add_argument(
            "--domain",
            type=str,
            help="Only process a specific domain (by name)",
        )
        parser.add_argument(
            "--reverse",
            action="store_true",
            help="Remove domain-level admin role assignments created by this command",
        )
        parser.add_argument(
            "--roles",
            type=str,
            nargs="+",
            help="Override which roles to assign (default: core.domain_owner + plugin admins)",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        domain_filter = options["domain"]
        reverse = options["reverse"]
        role_names = options["roles"] or ADMIN_ROLE_NAMES

        if reverse:
            self._reverse(role_names, domain_filter, dry_run)
            return

        # Fetch roles that exist
        roles = list(Role.objects.filter(name__in=role_names))
        found_names = {r.name for r in roles}
        missing = set(role_names) - found_names

        if missing:
            self.stderr.write(
                self.style.WARNING(f"Roles not found (plugin not installed?): {missing}")
            )

        if not roles:
            self.stderr.write(self.style.ERROR("No matching roles found. Aborting."))
            return

        self.stdout.write(f"Roles to assign: {[r.name for r in roles]}")
        self.stdout.write("")

        # Build queryset of DomainOrg records to process
        domain_orgs = DomainOrg.objects.prefetch_related("domains").all()

        if domain_filter:
            try:
                domain_obj = Domain.objects.get(name=domain_filter)
            except Domain.DoesNotExist:
                self.stderr.write(self.style.ERROR(f"Domain '{domain_filter}' not found."))
                return
            domain_orgs = domain_orgs.filter(domains=domain_obj)

        user_roles_to_create = []
        group_roles_to_create = []
        stats = {"domains_seen": set(), "users": 0, "groups": 0, "skipped_existing": 0}

        for domain_org in domain_orgs:
            domains = list(domain_org.domains.all())
            if not domains:
                continue

            for domain in domains:
                stats["domains_seen"].add(domain.name)

                for role in roles:
                    if domain_org.user_id:
                        # Check if already exists
                        exists = UserRole.objects.filter(
                            user_id=domain_org.user_id,
                            role=role,
                            object_id=None,
                            domain=domain,
                        ).exists()

                        if exists:
                            stats["skipped_existing"] += 1
                        else:
                            user_roles_to_create.append(
                                UserRole(
                                    user_id=domain_org.user_id,
                                    role=role,
                                    content_type=None,
                                    object_id=None,
                                    domain=domain,
                                )
                            )
                            stats["users"] += 1

                    if domain_org.group_id:
                        exists = GroupRole.objects.filter(
                            group_id=domain_org.group_id,
                            role=role,
                            object_id=None,
                            domain=domain,
                        ).exists()

                        if exists:
                            stats["skipped_existing"] += 1
                        else:
                            group_roles_to_create.append(
                                GroupRole(
                                    group_id=domain_org.group_id,
                                    role=role,
                                    content_type=None,
                                    object_id=None,
                                    domain=domain,
                                )
                            )
                            stats["groups"] += 1

        # Summary
        self.stdout.write(f"Domains: {len(stats['domains_seen'])}")
        self.stdout.write(f"User role assignments to create: {stats['users']}")
        self.stdout.write(f"Group role assignments to create: {stats['groups']}")
        self.stdout.write(f"Already existing (skipped): {stats['skipped_existing']}")
        self.stdout.write("")

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN — no changes made."))
            self._print_preview(user_roles_to_create, group_roles_to_create)
            return

        # Execute
        if user_roles_to_create:
            UserRole.objects.bulk_create(user_roles_to_create, ignore_conflicts=True)
            self.stdout.write(
                self.style.SUCCESS(f"Created {len(user_roles_to_create)} user role assignments.")
            )

        if group_roles_to_create:
            GroupRole.objects.bulk_create(group_roles_to_create, ignore_conflicts=True)
            self.stdout.write(
                self.style.SUCCESS(f"Created {len(group_roles_to_create)} group role assignments.")
            )

        if not user_roles_to_create and not group_roles_to_create:
            self.stdout.write(self.style.SUCCESS("Nothing to do — all roles already assigned."))

    def _reverse(self, role_names, domain_filter, dry_run):
        """Remove domain-level role assignments."""
        roles = Role.objects.filter(name__in=role_names)

        user_qs = UserRole.objects.filter(role__in=roles, object_id=None, domain__isnull=False)
        group_qs = GroupRole.objects.filter(role__in=roles, object_id=None, domain__isnull=False)

        if domain_filter:
            try:
                domain_obj = Domain.objects.get(name=domain_filter)
            except Domain.DoesNotExist:
                self.stderr.write(self.style.ERROR(f"Domain '{domain_filter}' not found."))
                return
            user_qs = user_qs.filter(domain=domain_obj)
            group_qs = group_qs.filter(domain=domain_obj)

        user_count = user_qs.count()
        group_count = group_qs.count()

        self.stdout.write(f"User role assignments to delete: {user_count}")
        self.stdout.write(f"Group role assignments to delete: {group_count}")

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN — no changes made."))
            return

        user_qs.delete()
        group_qs.delete()
        self.stdout.write(self.style.SUCCESS("Done."))

    def _print_preview(self, user_roles, group_roles):
        """Print a preview of what would be created."""
        if user_roles:
            self.stdout.write("\nUser assignments:")
            for ur in user_roles[:20]:
                self.stdout.write(
                    f"  user_id={ur.user_id} → role={ur.role.name} → domain={ur.domain.name}"
                )
            if len(user_roles) > 20:
                self.stdout.write(f"  ... and {len(user_roles) - 20} more")

        if group_roles:
            self.stdout.write("\nGroup assignments:")
            for gr in group_roles[:20]:
                self.stdout.write(
                    f"  group_id={gr.group_id} → role={gr.role.name} → domain={gr.domain.name}"
                )
            if len(group_roles) > 20:
                self.stdout.write(f"  ... and {len(group_roles) - 20} more")
