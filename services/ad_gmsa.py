"""Group Managed Service Account (gMSA) viewer service."""

from ldap3 import SUBTREE
from flask import current_app

from .ad_connection import get_connection

GMSA_ATTRIBUTES = [
    'cn', 'sAMAccountName', 'distinguishedName', 'description',
    'dNSHostName', 'userAccountControl', 'whenCreated', 'whenChanged',
    'msDS-GroupMSAMembership', 'msDS-ManagedPasswordInterval',
    'servicePrincipalName', 'memberOf',
    'msDS-ManagedPasswordId',
]


def _format_gmsa(entry):
    uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 0
    status = 'disabled' if uac & 2 else 'enabled'

    spns = []
    try:
        if entry.servicePrincipalName and entry.servicePrincipalName.values:
            spns = [str(v) for v in entry.servicePrincipalName.values]
    except Exception:
        pass

    member_of = []
    try:
        if entry.memberOf and entry.memberOf.values:
            member_of = [str(v) for v in entry.memberOf.values]
    except Exception:
        pass

    pwd_interval = ''
    try:
        attr = getattr(entry, 'msDS-ManagedPasswordInterval', None)
        if attr and attr.value:
            pwd_interval = str(attr.value)
    except Exception:
        pass

    return {
        'dn': str(entry.entry_dn),
        'cn': str(entry.cn) if entry.cn else '',
        'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
        'description': str(entry.description) if entry.description else '',
        'dns_name': str(entry.dNSHostName) if entry.dNSHostName else '',
        'status': status,
        'when_created': str(entry.whenCreated) if entry.whenCreated else '',
        'when_changed': str(entry.whenChanged) if entry.whenChanged else '',
        'spns': spns,
        'member_of': member_of,
        'pwd_interval': pwd_interval,
    }


def get_all_gmsas():
    """Get all gMSA accounts in the domain."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        ldap_filter = '(objectClass=msDS-GroupManagedServiceAccount)'
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=GMSA_ATTRIBUTES, paged_size=500)
        gmsas = [_format_gmsa(e) for e in conn.entries]
        return True, gmsas
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_gmsa_detail(sam):
    """Get detailed info for a specific gMSA."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        ldap_filter = f'(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName={sam}))'
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=GMSA_ATTRIBUTES)
        if not conn.entries:
            return False, 'gMSA not found'
        return True, _format_gmsa(conn.entries[0])
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
