"""Custom LDAP query execution service."""

from ldap3 import SUBTREE, BASE, LEVEL
from flask import current_app

from .ad_connection import get_connection

SCOPE_MAP = {
    'subtree': SUBTREE,
    'base': BASE,
    'onelevel': LEVEL,
}

# Commonly used LDAP filters for quick selection
SAVED_QUERIES = {
    'all_users': {
        'name': 'All Users',
        'filter': '(&(objectClass=user)(objectCategory=person))',
        'attrs': 'cn,sAMAccountName,mail,department,title,userAccountControl',
    },
    'disabled_users': {
        'name': 'Disabled Users',
        'filter': '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))',
        'attrs': 'cn,sAMAccountName,whenChanged',
    },
    'locked_accounts': {
        'name': 'Locked Accounts',
        'filter': '(&(objectClass=user)(objectCategory=person)(lockoutTime>=1))',
        'attrs': 'cn,sAMAccountName,lockoutTime',
    },
    'all_groups': {
        'name': 'All Groups',
        'filter': '(objectClass=group)',
        'attrs': 'cn,sAMAccountName,groupType,description',
    },
    'all_computers': {
        'name': 'All Computers',
        'filter': '(objectClass=computer)',
        'attrs': 'cn,operatingSystem,lastLogonTimestamp',
    },
    'empty_groups': {
        'name': 'Empty Groups (no members)',
        'filter': '(&(objectClass=group)(!(member=*)))',
        'attrs': 'cn,sAMAccountName,description',
    },
    'never_logged_in': {
        'name': 'Users Never Logged In',
        'filter': '(&(objectClass=user)(objectCategory=person)(!(lastLogon=*)))',
        'attrs': 'cn,sAMAccountName,whenCreated',
    },
    'password_never_expires': {
        'name': 'Password Never Expires',
        'filter': '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
        'attrs': 'cn,sAMAccountName,pwdLastSet',
    },
}

MAX_RESULTS = 1000


def execute_query(search_base, ldap_filter, attributes_str, scope='subtree'):
    """Execute a custom LDAP query and return results."""
    cfg = current_app.config
    if not search_base:
        search_base = cfg['BASE_DN']

    # Parse attributes
    if attributes_str and attributes_str.strip() != '*':
        attributes = [a.strip() for a in attributes_str.split(',') if a.strip()]
    else:
        attributes = ['cn', 'sAMAccountName', 'objectClass', 'distinguishedName']

    search_scope = SCOPE_MAP.get(scope, SUBTREE)

    conn = None
    try:
        conn = get_connection()
        conn.search(
            search_base, ldap_filter,
            search_scope=search_scope,
            attributes=attributes,
            paged_size=MAX_RESULTS,
        )

        results = []
        for entry in conn.entries:
            row = {'dn': str(entry.entry_dn)}
            for attr in attributes:
                try:
                    val = getattr(entry, attr, None)
                    if val is None:
                        row[attr] = ''
                    elif hasattr(val, 'values') and val.values:
                        if len(val.values) > 1:
                            row[attr] = '; '.join(str(v) for v in val.values)
                        else:
                            row[attr] = str(val.value) if val.value else ''
                    elif hasattr(val, 'value'):
                        row[attr] = str(val.value) if val.value else ''
                    else:
                        row[attr] = str(val) if val else ''
                except Exception:
                    row[attr] = ''
            results.append(row)

        return True, {'results': results, 'count': len(results), 'attributes': attributes}
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
