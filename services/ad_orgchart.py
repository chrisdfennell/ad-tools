"""Org chart service - build manager hierarchy tree."""

from ldap3 import SUBTREE
from flask import current_app

from .ad_connection import get_connection

USER_FILTER = '(&(objectClass=user)(objectCategory=person))'


def get_org_tree():
    """Build a hierarchical org chart from manager attributes."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # Get all users with their manager field
        conn.search(
            cfg['BASE_DN'], USER_FILTER, search_scope=SUBTREE,
            attributes=['cn', 'sAMAccountName', 'displayName', 'title',
                         'department', 'manager', 'userAccountControl',
                         'distinguishedName'],
        )

        users_by_dn = {}
        for entry in conn.entries:
            dn = str(entry.entry_dn)
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 512
            if uac & 2:
                continue  # Skip disabled accounts

            manager_dn = ''
            try:
                manager_dn = str(entry.manager) if entry.manager.value else ''
            except Exception:
                pass

            users_by_dn[dn] = {
                'dn': dn,
                'cn': str(entry.cn),
                'sam': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName.value else str(entry.cn),
                'title': str(entry.title) if entry.title.value else '',
                'department': str(entry.department) if entry.department.value else '',
                'manager_dn': manager_dn,
                'children': [],
            }

        # Build tree: find roots (no manager or manager not in our user set)
        roots = []
        for dn, user in users_by_dn.items():
            mgr = user['manager_dn']
            if mgr and mgr in users_by_dn:
                users_by_dn[mgr]['children'].append(user)
            else:
                roots.append(user)

        # Sort children at each level
        def sort_tree(nodes):
            nodes.sort(key=lambda n: n['display_name'].lower())
            for node in nodes:
                sort_tree(node['children'])

        sort_tree(roots)

        return True, roots
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_direct_reports(manager_sam):
    """Get direct reports for a specific user."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # First find the manager's DN
        mgr_filter = f'(&{USER_FILTER}(sAMAccountName={manager_sam}))'
        conn.search(cfg['BASE_DN'], mgr_filter, search_scope=SUBTREE,
                     attributes=['distinguishedName', 'cn', 'displayName', 'title', 'department'])
        if not conn.entries:
            return False, 'Manager not found'
        manager_dn = str(conn.entries[0].entry_dn)
        manager_info = {
            'dn': manager_dn,
            'cn': str(conn.entries[0].cn),
            'display_name': str(conn.entries[0].displayName) if conn.entries[0].displayName.value else '',
            'title': str(conn.entries[0].title) if conn.entries[0].title.value else '',
            'department': str(conn.entries[0].department) if conn.entries[0].department.value else '',
        }

        # Find direct reports
        report_filter = f'(&{USER_FILTER}(manager={manager_dn}))'
        conn.search(cfg['BASE_DN'], report_filter, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'displayName', 'title',
                                 'department', 'distinguishedName'])

        reports = []
        for entry in conn.entries:
            reports.append({
                'cn': str(entry.cn),
                'sam': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName.value else str(entry.cn),
                'title': str(entry.title) if entry.title.value else '',
                'department': str(entry.department) if entry.department.value else '',
                'dn': str(entry.entry_dn),
            })

        reports.sort(key=lambda r: r['display_name'].lower())
        return True, {'manager': manager_info, 'reports': reports}
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
