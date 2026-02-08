from ldap3 import SUBTREE, MODIFY_REPLACE
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection

COMPUTER_ATTRIBUTES = [
    'cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem',
    'operatingSystemVersion', 'lastLogonTimestamp', 'whenCreated',
    'userAccountControl', 'distinguishedName', 'description',
    'operatingSystemServicePack', 'managedBy',
]


def _format_computer(entry):
    uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 4096
    status = 'disabled' if uac & 2 else 'enabled'
    return {
        'dn': str(entry.entry_dn),
        'cn': str(entry.cn) if entry.cn else '',
        'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
        'dns_name': str(entry.dNSHostName) if entry.dNSHostName else '',
        'os': str(entry.operatingSystem) if entry.operatingSystem else '',
        'os_version': str(entry.operatingSystemVersion) if entry.operatingSystemVersion else '',
        'description': str(entry.description) if entry.description else '',
        'status': status,
        'last_logon': str(entry.lastLogonTimestamp) if entry.lastLogonTimestamp.value else 'Never',
        'when_created': str(entry.whenCreated) if entry.whenCreated else '',
        'managed_by': str(entry.managedBy) if entry.managedBy else '',
    }


def search_computers(query='*'):
    cfg = current_app.config
    search_base = cfg.get('COMPUTERS_OU') or cfg['BASE_DN']
    if query and query != '*':
        ldap_filter = f'(&(objectClass=computer)(cn=*{escape_rdn(query)}*))'
    else:
        ldap_filter = '(objectClass=computer)'

    conn = None
    try:
        conn = get_connection()
        conn.search(search_base, ldap_filter, search_scope=SUBTREE,
                     attributes=COMPUTER_ATTRIBUTES, paged_size=1000)
        computers = [_format_computer(e) for e in conn.entries]
        return True, computers
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_computer(cn):
    cfg = current_app.config
    ldap_filter = f'(&(objectClass=computer)(cn={escape_rdn(cn)}))'
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=COMPUTER_ATTRIBUTES)
        if not conn.entries:
            return False, 'Computer not found'
        return True, _format_computer(conn.entries[0])
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_computer_groups(computer_dn):
    """Get groups a computer is a member of."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        ldap_filter = f'(member={computer_dn})'
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=['cn', 'distinguishedName', 'groupType'])
        groups = []
        for e in conn.entries:
            groups.append({
                'dn': str(e.entry_dn),
                'cn': str(e.cn) if e.cn else '',
            })
        return True, groups
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def create_computer(name, ou_dn, description=''):
    """Create a new computer account in AD."""
    computer_dn = f"CN={escape_rdn(name)},{ou_dn}"
    sam_name = name.upper()
    if not sam_name.endswith('$'):
        sam_name += '$'
    attributes = {
        'cn': name,
        'sAMAccountName': sam_name,
        'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
        'userAccountControl': 4128,  # WORKSTATION_TRUST_ACCOUNT + PASSWD_NOTREQD
    }
    if description:
        attributes['description'] = description

    conn = None
    try:
        conn = get_connection()
        if not conn.add(computer_dn, attributes=attributes):
            return False, conn.result.get('description', 'Failed to create computer')
        return True, f"Computer '{name}' created successfully."
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def delete_computer(computer_dn):
    """Delete a computer account from AD."""
    conn = None
    try:
        conn = get_connection()
        if not conn.delete(computer_dn):
            return False, conn.result.get('description', 'Delete failed')
        return True, 'Computer deleted successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def disable_computer(computer_dn):
    conn = None
    try:
        conn = get_connection()
        conn.search(current_app.config['BASE_DN'],
                     f'(distinguishedName={computer_dn})',
                     attributes=['userAccountControl'])
        if not conn.entries:
            return False, 'Computer not found'
        current_uac = int(conn.entries[0].userAccountControl.value)
        new_uac = current_uac | 2
        if not conn.modify(computer_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]}):
            return False, conn.result.get('description', 'Failed to disable')
        return True, 'Computer disabled.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def enable_computer(computer_dn):
    conn = None
    try:
        conn = get_connection()
        conn.search(current_app.config['BASE_DN'],
                     f'(distinguishedName={computer_dn})',
                     attributes=['userAccountControl'])
        if not conn.entries:
            return False, 'Computer not found'
        current_uac = int(conn.entries[0].userAccountControl.value)
        new_uac = current_uac & ~2
        if not conn.modify(computer_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]}):
            return False, conn.result.get('description', 'Failed to enable')
        return True, 'Computer enabled.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
