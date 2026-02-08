"""Bulk attribute editor - modify a single attribute across multiple objects."""

from ldap3 import SUBTREE, MODIFY_REPLACE
from flask import current_app

from .ad_connection import get_connection


# Common attributes safe for bulk editing
BULK_SAFE_ATTRIBUTES = [
    'department', 'company', 'title', 'description',
    'physicalDeliveryOfficeName', 'l', 'st', 'co', 'c',
    'streetAddress', 'postalCode', 'telephoneNumber',
    'extensionAttribute1', 'extensionAttribute2', 'extensionAttribute3',
    'extensionAttribute4', 'extensionAttribute5',
    'extensionAttribute6', 'extensionAttribute7', 'extensionAttribute8',
    'extensionAttribute9', 'extensionAttribute10',
    'extensionAttribute11', 'extensionAttribute12', 'extensionAttribute13',
    'extensionAttribute14', 'extensionAttribute15',
]

USER_FILTER = '(&(objectClass=user)(objectCategory=person))'


def search_objects(query, obj_type='users'):
    """Search for users or computers to include in bulk edit."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        if obj_type == 'computers':
            ldap_filter = f'(&(objectClass=computer)(cn=*{query}*))'
        else:
            ldap_filter = f'(&{USER_FILTER}(|(cn=*{query}*)(sAMAccountName=*{query}*)))'

        conn.search(
            cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
            attributes=['cn', 'sAMAccountName', 'distinguishedName'],
            size_limit=50,
        )
        results = []
        for e in conn.entries:
            results.append({
                'cn': str(e['cn'].value or ''),
                'sam': str(e['sAMAccountName'].value or ''),
                'dn': str(e.entry_dn),
            })
        return True, results
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def bulk_modify_attribute(dns, attribute, value, clear=False):
    """Modify a single attribute on multiple objects.

    Args:
        dns: list of DNs to modify
        attribute: attribute name to change
        value: new value to set
        clear: if True, clears the attribute instead of setting it

    Returns:
        (success_count, fail_count, errors_list)
    """
    conn = None
    success_count = 0
    fail_count = 0
    errors = []
    try:
        conn = get_connection()

        for dn in dns:
            try:
                if clear:
                    modification = {attribute: [(MODIFY_REPLACE, [])]}
                else:
                    modification = {attribute: [(MODIFY_REPLACE, [value])]}

                if conn.modify(dn, modification):
                    success_count += 1
                else:
                    fail_count += 1
                    desc = conn.result.get('description', 'Unknown error')
                    errors.append(f'{dn}: {desc}')
            except Exception as e:
                fail_count += 1
                errors.append(f'{dn}: {str(e)}')

        return success_count, fail_count, errors
    except Exception as e:
        return 0, len(dns), [str(e)]
    finally:
        if conn:
            conn.unbind()
