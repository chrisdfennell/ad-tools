"""Role-Based Access Control (RBAC) service.

Defines roles and permissions for the application.
Roles are mapped to AD groups:
  - admin: Domain Admins (full access)
  - helpdesk: Configurable AD group (limited access)
  - viewer: Configurable AD group (read-only access)
"""

import ssl
from functools import wraps

from flask import session, flash, redirect, url_for, current_app
from ldap3 import Server, Connection, NTLM, Tls, SUBTREE, ALL


# Permission definitions per role
ROLE_PERMISSIONS = {
    'admin': {
        'users.view', 'users.create', 'users.edit', 'users.delete',
        'users.disable', 'users.enable', 'users.unlock', 'users.reset_password',
        'users.move', 'users.bulk', 'users.copy', 'users.compare',
        'groups.view', 'groups.create', 'groups.delete', 'groups.manage_members',
        'computers.view', 'computers.disable', 'computers.enable', 'computers.move',
        'ous.view', 'ous.create', 'ous.delete', 'ous.move',
        'reports.view', 'audit.view',
        'recycle.view', 'recycle.restore',
        'attributes.view', 'attributes.edit',
        'search.view', 'orgchart.view',
        'gpo.view', 'gpo.manage_links',
        'delegation.view', 'service_accounts.view',
        'dns.view', 'activity.view',
        'laps.view', 'bitlocker.view',
        'fgpp.view', 'fgpp.edit',
        'group_nesting.view', 'ad_health.view',
        'scheduled_reports.view', 'scheduled_reports.manage',
        'photos.view', 'photos.edit',
        'rbac.manage',
        # Round 2 permissions
        'groups.edit',
        'computers.create', 'computers.delete',
        'bulk_groups.view', 'bulk_groups.manage',
        'ldap_query.view', 'ldap_query.execute',
        'gmsa.view', 'spn.view', 'spn.manage',
        'token_size.view',
        'workflows.onboard', 'workflows.offboard',
        'reports.export',
        # Round 3 permissions
        'lockout.view',
        'sites.view',
        'acl.view',
        'bulk_attr.edit',
        'schema.view',
        'replication.view',
        'dynamic_groups.view', 'dynamic_groups.manage',
        'settings.manage',
    },
    'helpdesk': {
        'users.view', 'users.unlock', 'users.reset_password',
        'users.disable', 'users.enable', 'users.compare',
        'groups.view',
        'computers.view', 'computers.disable', 'computers.enable',
        'ous.view',
        'reports.view', 'audit.view',
        'search.view', 'orgchart.view',
        'activity.view',
        'laps.view', 'bitlocker.view',
        'group_nesting.view',
        'photos.view', 'photos.edit',
        'gpo.view', 'dns.view',
        'service_accounts.view', 'delegation.view',
        'gmsa.view', 'spn.view', 'token_size.view',
        'reports.export',
        'lockout.view',
        'sites.view', 'schema.view',
        'dynamic_groups.view',
    },
    'viewer': {
        'users.view', 'users.compare',
        'groups.view',
        'computers.view',
        'ous.view',
        'reports.view',
        'search.view', 'orgchart.view',
        'activity.view',
        'group_nesting.view',
        'gpo.view', 'dns.view',
        'gmsa.view', 'token_size.view',
        'reports.export',
        'lockout.view',
        'sites.view', 'schema.view',
        'dynamic_groups.view',
    },
}


def get_user_role(cfg, username):
    """Determine the user's role based on AD group membership.

    Returns the highest-privilege role the user qualifies for.
    """
    try:
        tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        server = Server(
            f"ldaps://{cfg['AD_SERVER_IP']}:636",
            get_info=ALL, use_ssl=True, tls=tls_config,
        )
        conn = Connection(
            server,
            user=f"{cfg['AD_DOMAIN']}\\{cfg['AD_USER']}",
            password=cfg['AD_PASSWORD'],
            authentication=NTLM, auto_bind=True,
        )

        # Find the user's DN
        user_filter = (
            f'(&(objectClass=user)(objectCategory=person)'
            f'(sAMAccountName={username}))'
        )
        conn.search(cfg['BASE_DN'], user_filter, search_scope=SUBTREE,
                     attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            return None

        # Check Domain Admins (always = admin role)
        da_role = _check_group_membership(conn, cfg, username, 'Domain Admins')
        if da_role:
            conn.unbind()
            return 'admin'

        # Check configurable helpdesk group
        helpdesk_group = cfg.get('HELPDESK_GROUP', '')
        if helpdesk_group:
            hd_role = _check_group_membership(conn, cfg, username, helpdesk_group)
            if hd_role:
                conn.unbind()
                return 'helpdesk'

        # Check configurable viewer group
        viewer_group = cfg.get('VIEWER_GROUP', '')
        if viewer_group:
            vw_role = _check_group_membership(conn, cfg, username, viewer_group)
            if vw_role:
                conn.unbind()
                return 'viewer'

        conn.unbind()
        return None
    except Exception:
        return None


def _check_group_membership(conn, cfg, username, group_name):
    """Check if user is a member of a group (including nested membership)."""
    conn.search(cfg['BASE_DN'],
                f'(&(objectClass=group)(cn={group_name}))',
                search_scope=SUBTREE,
                attributes=['distinguishedName'])
    if not conn.entries:
        return False
    group_dn = str(conn.entries[0].entry_dn)

    user_filter = (
        f'(&(objectClass=user)(objectCategory=person)'
        f'(sAMAccountName={username})'
        f'(memberOf:1.2.840.113556.1.4.1941:={group_dn}))'
    )
    conn.search(cfg['BASE_DN'], user_filter, search_scope=SUBTREE,
                 attributes=['distinguishedName'])
    return len(conn.entries) > 0


def has_permission(permission):
    """Check if the current session user has a specific permission."""
    role = session.get('role', '')
    if not role:
        return False
    permissions = ROLE_PERMISSIONS.get(role, set())
    return permission in permissions


def require_permission(permission):
    """Decorator to require a specific permission for a route."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_permission(permission):
                flash('You do not have permission to access this feature.', 'danger')
                return redirect(url_for('dashboard.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
