"""Global search service - search across all AD object types."""

from ldap3 import SUBTREE
from flask import current_app

from .ad_connection import get_connection


def global_search(query):
    """Search across users, groups, computers, and OUs simultaneously."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        escaped_q = query.replace('(', '\\28').replace(')', '\\29').replace('*', '\\2a').replace('\\', '\\5c')
        results = {'users': [], 'groups': [], 'computers': [], 'ous': []}

        # Search users
        user_filter = (
            f'(&(objectClass=user)(objectCategory=person)'
            f'(|(cn=*{escaped_q}*)(sAMAccountName=*{escaped_q}*)'
            f'(mail=*{escaped_q}*)(displayName=*{escaped_q}*)'
            f'(department=*{escaped_q}*)))'
        )
        conn.search(cfg['BASE_DN'], user_filter, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'displayName', 'mail',
                                 'department', 'userAccountControl', 'distinguishedName'],
                     size_limit=25)
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 512
            status = 'disabled' if uac & 2 else 'enabled'
            results['users'].append({
                'cn': str(entry.cn),
                'sam': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName.value else '',
                'mail': str(entry.mail) if entry.mail.value else '',
                'department': str(entry.department) if entry.department.value else '',
                'status': status,
                'dn': str(entry.entry_dn),
            })

        # Search groups
        group_filter = f'(&(objectClass=group)(|(cn=*{escaped_q}*)(description=*{escaped_q}*)))'
        conn.search(cfg['BASE_DN'], group_filter, search_scope=SUBTREE,
                     attributes=['cn', 'description', 'groupType', 'member', 'distinguishedName'],
                     size_limit=25)
        for entry in conn.entries:
            member_count = len(entry.member.values) if entry.member.value else 0
            results['groups'].append({
                'cn': str(entry.cn),
                'description': str(entry.description) if entry.description.value else '',
                'member_count': member_count,
                'dn': str(entry.entry_dn),
            })

        # Search computers
        comp_filter = f'(&(objectClass=computer)(|(cn=*{escaped_q}*)(sAMAccountName=*{escaped_q}*)))'
        conn.search(cfg['BASE_DN'], comp_filter, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'operatingSystem',
                                 'userAccountControl', 'distinguishedName'],
                     size_limit=25)
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 4096
            status = 'disabled' if uac & 2 else 'enabled'
            os_name = ''
            try:
                os_name = str(entry.operatingSystem) if entry.operatingSystem.value else ''
            except Exception:
                pass
            results['computers'].append({
                'cn': str(entry.cn),
                'sam': str(entry.sAMAccountName),
                'os': os_name,
                'status': status,
                'dn': str(entry.entry_dn),
            })

        # Search OUs
        ou_filter = f'(&(objectClass=organizationalUnit)(|(ou=*{escaped_q}*)(description=*{escaped_q}*)))'
        conn.search(cfg['BASE_DN'], ou_filter, search_scope=SUBTREE,
                     attributes=['ou', 'description', 'distinguishedName'],
                     size_limit=25)
        for entry in conn.entries:
            results['ous'].append({
                'name': str(entry.ou),
                'description': str(entry.description) if entry.description.value else '',
                'dn': str(entry.entry_dn),
            })

        total = sum(len(v) for v in results.values())
        return True, results, total
    except Exception as e:
        return False, str(e), 0
    finally:
        if conn:
            conn.unbind()
