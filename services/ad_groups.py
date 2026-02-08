from ldap3 import SUBTREE, MODIFY_REPLACE
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection

GROUP_ATTRIBUTES = [
    'cn', 'sAMAccountName', 'distinguishedName', 'description',
    'groupType', 'member', 'memberOf', 'whenCreated', 'whenChanged',
    'managedBy',
]

# groupType values
GROUP_TYPES = {
    'global_security': -2147483646,
    'domain_local_security': -2147483644,
    'universal_security': -2147483640,
    'global_distribution': 2,
    'domain_local_distribution': 4,
    'universal_distribution': 8,
}

GROUP_TYPE_LABELS = {
    -2147483646: 'Global Security',
    -2147483644: 'Domain Local Security',
    -2147483640: 'Universal Security',
    2: 'Global Distribution',
    4: 'Domain Local Distribution',
    8: 'Universal Distribution',
}


def _format_group(entry):
    gt = int(entry.groupType.value) if entry.groupType.value else 0
    members = [str(m) for m in entry.member] if entry.member else []
    return {
        'dn': str(entry.entry_dn),
        'cn': str(entry.cn) if entry.cn else '',
        'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
        'description': str(entry.description) if entry.description else '',
        'group_type': gt,
        'group_type_label': GROUP_TYPE_LABELS.get(gt, f'Unknown ({gt})'),
        'member_count': len(members),
        'members': members,
        'member_of': [str(g) for g in entry.memberOf] if entry.memberOf else [],
        'managed_by': str(entry.managedBy) if entry.managedBy else '',
        'when_created': str(entry.whenCreated) if entry.whenCreated else '',
    }


def search_groups(query='*'):
    cfg = current_app.config
    search_base = cfg.get('GROUPS_OU') or cfg['BASE_DN']
    if query and query != '*':
        ldap_filter = f'(&(objectClass=group)(cn=*{escape_rdn(query)}*))'
    else:
        ldap_filter = '(objectClass=group)'

    conn = None
    try:
        conn = get_connection()
        conn.search(search_base, ldap_filter, search_scope=SUBTREE,
                     attributes=GROUP_ATTRIBUTES, paged_size=1000)
        groups = [_format_group(e) for e in conn.entries]
        return True, groups
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_group(group_cn):
    cfg = current_app.config
    ldap_filter = f'(&(objectClass=group)(cn={escape_rdn(group_cn)}))'
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=GROUP_ATTRIBUTES)
        if not conn.entries:
            return False, 'Group not found'
        return True, _format_group(conn.entries[0])
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def create_group(name, ou_dn, group_type_key='global_security', description=''):
    group_dn = f"CN={escape_rdn(name)},{ou_dn}"
    gt = GROUP_TYPES.get(group_type_key, -2147483646)
    attributes = {
        'cn': name,
        'sAMAccountName': name,
        'groupType': gt,
        'objectClass': ['top', 'group'],
    }
    if description:
        attributes['description'] = description

    conn = None
    try:
        conn = get_connection()
        if not conn.add(group_dn, attributes=attributes):
            return False, conn.result.get('description', 'Failed to create group')
        return True, f"Group '{name}' created successfully."
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def delete_group(group_dn):
    conn = None
    try:
        conn = get_connection()
        if not conn.delete(group_dn):
            return False, conn.result.get('description', 'Delete failed')
        return True, 'Group deleted successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def add_member(group_dn, member_dn):
    conn = None
    try:
        conn = get_connection()
        conn.extend.microsoft.add_members_to_groups(member_dn, group_dn)
        return True, 'Member added successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def remove_member(group_dn, member_dn):
    conn = None
    try:
        conn = get_connection()
        conn.extend.microsoft.remove_members_from_groups(member_dn, group_dn)
        return True, 'Member removed successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def modify_group(group_dn, changes):
    """Modify group attributes. changes is a dict of {attr_name: new_value}."""
    conn = None
    try:
        conn = get_connection()
        modifications = {}
        for attr, value in changes.items():
            if value:
                modifications[attr] = [(MODIFY_REPLACE, [value])]
            else:
                modifications[attr] = [(MODIFY_REPLACE, [])]
        if not modifications:
            return True, 'No changes to apply.'
        if not conn.modify(group_dn, modifications):
            return False, conn.result.get('description', 'Modification failed')
        return True, 'Group updated successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_group_members(group_dn, recursive=False):
    """Get members of a group. If recursive, uses LDAP_MATCHING_RULE_IN_CHAIN."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        if recursive:
            ldap_filter = f'(memberOf:1.2.840.113556.1.4.1941:={group_dn})'
        else:
            ldap_filter = f'(memberOf={group_dn})'
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'objectClass', 'distinguishedName'])
        members = []
        for e in conn.entries:
            obj_classes = [str(c) for c in e.objectClass]
            obj_type = 'user' if 'user' in obj_classes else 'group' if 'group' in obj_classes else 'other'
            members.append({
                'dn': str(e.entry_dn),
                'cn': str(e.cn) if e.cn else '',
                'sam': str(e.sAMAccountName) if e.sAMAccountName else '',
                'type': obj_type,
            })
        return True, members
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
