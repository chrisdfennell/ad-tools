"""Service Principal Name (SPN) management service."""

from ldap3 import SUBTREE, MODIFY_ADD, MODIFY_DELETE
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection


def search_spns(query='*'):
    """Search for objects with SPNs matching the query."""
    cfg = current_app.config
    if query and query != '*':
        ldap_filter = f'(servicePrincipalName=*{escape_rdn(query)}*)'
    else:
        ldap_filter = '(servicePrincipalName=*)'

    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'servicePrincipalName',
                                 'objectClass', 'distinguishedName'],
                     paged_size=500)

        results = []
        for entry in conn.entries:
            obj_classes = [str(c) for c in entry.objectClass]
            if 'computer' in obj_classes:
                obj_type = 'computer'
            elif 'msDS-GroupManagedServiceAccount' in obj_classes:
                obj_type = 'gmsa'
            elif 'user' in obj_classes:
                obj_type = 'user'
            else:
                obj_type = 'other'

            spns = []
            if entry.servicePrincipalName and entry.servicePrincipalName.values:
                spns = [str(v) for v in entry.servicePrincipalName.values]

            results.append({
                'dn': str(entry.entry_dn),
                'cn': str(entry.cn) if entry.cn else '',
                'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'type': obj_type,
                'spns': spns,
                'spn_count': len(spns),
            })
        return True, results
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_spns_for_object(sam):
    """Get SPNs for a specific object by sAMAccountName."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        ldap_filter = f'(sAMAccountName={escape_rdn(sam)})'
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'servicePrincipalName',
                                 'objectClass', 'distinguishedName'])
        if not conn.entries:
            return False, 'Object not found'

        entry = conn.entries[0]
        spns = []
        if entry.servicePrincipalName and entry.servicePrincipalName.values:
            spns = [str(v) for v in entry.servicePrincipalName.values]

        obj_classes = [str(c) for c in entry.objectClass]
        if 'computer' in obj_classes:
            obj_type = 'computer'
        elif 'msDS-GroupManagedServiceAccount' in obj_classes:
            obj_type = 'gmsa'
        elif 'user' in obj_classes:
            obj_type = 'user'
        else:
            obj_type = 'other'

        return True, {
            'dn': str(entry.entry_dn),
            'cn': str(entry.cn) if entry.cn else '',
            'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
            'type': obj_type,
            'spns': spns,
        }
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def add_spn(object_dn, spn):
    """Add an SPN to an object."""
    conn = None
    try:
        conn = get_connection()
        # Check for duplicates across the domain
        dup_success, dup_msg = check_duplicate_spn(spn, exclude_dn=object_dn)
        if not dup_success:
            return False, dup_msg

        if not conn.modify(object_dn, {'servicePrincipalName': [(MODIFY_ADD, [spn])]}):
            return False, conn.result.get('description', 'Failed to add SPN')
        return True, f'SPN "{spn}" added successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def remove_spn(object_dn, spn):
    """Remove an SPN from an object."""
    conn = None
    try:
        conn = get_connection()
        if not conn.modify(object_dn, {'servicePrincipalName': [(MODIFY_DELETE, [spn])]}):
            return False, conn.result.get('description', 'Failed to remove SPN')
        return True, f'SPN "{spn}" removed successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def check_duplicate_spn(spn, exclude_dn=None):
    """Check if an SPN already exists in the domain. Returns (True, None) if no dup, (False, msg) if dup."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        ldap_filter = f'(servicePrincipalName={escape_rdn(spn)})'
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=['cn', 'distinguishedName'])
        for entry in conn.entries:
            if exclude_dn and str(entry.entry_dn) == exclude_dn:
                continue
            return False, f'Duplicate SPN! Already registered on: {entry.cn} ({entry.entry_dn})'
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
