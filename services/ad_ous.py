from ldap3 import SUBTREE, LEVEL
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection


def get_ou_tree():
    """Get all OUs and build a nested tree structure."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], '(objectClass=organizationalUnit)',
                     search_scope=SUBTREE,
                     attributes=['ou', 'distinguishedName', 'description'])
        ous = []
        for entry in conn.entries:
            ous.append({
                'dn': str(entry.entry_dn),
                'name': str(entry.ou) if entry.ou else '',
                'description': str(entry.description) if entry.description else '',
            })
        # Sort by DN depth (shallowest first)
        ous.sort(key=lambda x: x['dn'].count(','))

        # Build tree
        tree = {'dn': cfg['BASE_DN'], 'name': cfg['BASE_DN'], 'children': [], 'description': ''}
        dn_map = {cfg['BASE_DN']: tree}

        for ou in ous:
            node = {'dn': ou['dn'], 'name': ou['name'], 'children': [], 'description': ou['description']}
            dn_map[ou['dn']] = node
            # Find parent DN
            parts = ou['dn'].split(',', 1)
            parent_dn = parts[1] if len(parts) > 1 else cfg['BASE_DN']
            parent = dn_map.get(parent_dn, tree)
            parent['children'].append(node)

        return True, tree
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_ou_contents(ou_dn):
    """Get immediate children of an OU (users, groups, computers, child OUs)."""
    conn = None
    try:
        conn = get_connection()
        conn.search(ou_dn, '(objectClass=*)', search_scope=LEVEL,
                     attributes=['cn', 'ou', 'objectClass', 'sAMAccountName',
                                 'distinguishedName', 'description'])
        contents = {'users': [], 'groups': [], 'computers': [], 'ous': []}
        for entry in conn.entries:
            obj_classes = [str(c).lower() for c in entry.objectClass]
            item = {
                'dn': str(entry.entry_dn),
                'name': str(entry.cn) if entry.cn else str(entry.ou) if entry.ou else '',
                'sam': str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') and entry.sAMAccountName else '',
            }
            if 'organizationalunit' in obj_classes:
                contents['ous'].append(item)
            elif 'computer' in obj_classes:
                contents['computers'].append(item)
            elif 'group' in obj_classes:
                contents['groups'].append(item)
            elif 'user' in obj_classes and 'computer' not in obj_classes:
                contents['users'].append(item)
        return True, contents
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def create_ou(name, parent_dn):
    ou_dn = f"OU={escape_rdn(name)},{parent_dn}"
    conn = None
    try:
        conn = get_connection()
        if not conn.add(ou_dn, 'organizationalUnit', {'description': ''}):
            return False, conn.result.get('description', 'Failed to create OU')
        return True, f"OU '{name}' created successfully."
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def delete_ou(ou_dn):
    conn = None
    try:
        conn = get_connection()
        if not conn.delete(ou_dn):
            desc = conn.result.get('description', 'Delete failed')
            if 'notAllowedOnNonLeaf' in desc:
                return False, 'Cannot delete OU: it is not empty. Remove all objects first.'
            return False, desc
        return True, 'OU deleted successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def move_object(object_dn, new_ou_dn):
    """Move an AD object to a different OU."""
    conn = None
    try:
        conn = get_connection()
        # Extract RDN from current DN
        rdn = object_dn.split(',')[0]
        if not conn.modify_dn(object_dn, rdn, new_superior=new_ou_dn):
            return False, conn.result.get('description', 'Move failed')
        return True, 'Object moved successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
