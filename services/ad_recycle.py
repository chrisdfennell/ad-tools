from ldap3 import SUBTREE, BASE
from ldap3.core.exceptions import LDAPException
from flask import current_app

from .ad_connection import get_connection


def get_deleted_objects():
    """Query the AD Recycle Bin for deleted objects."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        deleted_dn = f"CN=Deleted Objects,{cfg['BASE_DN']}"

        # Search deleted objects container with show_deleted control
        conn.search(
            deleted_dn,
            '(&(isDeleted=TRUE)(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit)))',
            search_scope=SUBTREE,
            attributes=['cn', 'sAMAccountName', 'objectClass', 'whenChanged',
                         'distinguishedName', 'lastKnownParent', 'isDeleted'],
            controls=[('1.2.840.113556.1.4.417', True, None)],  # LDAP_SERVER_SHOW_DELETED_OID
        )

        objects = []
        for entry in conn.entries:
            obj_classes = [str(c).lower() for c in entry.objectClass]
            if 'user' in obj_classes and 'computer' not in obj_classes:
                obj_type = 'User'
            elif 'computer' in obj_classes:
                obj_type = 'Computer'
            elif 'group' in obj_classes:
                obj_type = 'Group'
            elif 'organizationalunit' in obj_classes:
                obj_type = 'OU'
            else:
                obj_type = 'Other'

            cn = str(entry.cn) if entry.cn else ''
            # AD appends \nDEL:<GUID> to CN of deleted objects; clean it
            if '\n' in cn:
                cn = cn.split('\n')[0]
            if '\x0a' in cn:
                cn = cn.split('\x0a')[0]

            objects.append({
                'dn': str(entry.entry_dn),
                'cn': cn,
                'sam': str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') and entry.sAMAccountName else '',
                'type': obj_type,
                'when_deleted': str(entry.whenChanged) if entry.whenChanged else '',
                'last_known_parent': str(entry.lastKnownParent) if hasattr(entry, 'lastKnownParent') and entry.lastKnownParent else '',
            })

        objects.sort(key=lambda x: x['when_deleted'], reverse=True)
        return True, objects
    except LDAPException as e:
        err = str(e)
        if 'referral' in err.lower() or 'unwillingToPerform' in err:
            return False, 'AD Recycle Bin may not be enabled. Enable it in AD Administrative Center > domain > Enable Recycle Bin.'
        return False, err
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def restore_deleted_object(deleted_dn, new_ou_dn=None):
    """Restore a deleted object from the recycle bin."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # Get the object's original info
        conn.search(
            deleted_dn,
            '(isDeleted=TRUE)',
            search_scope=BASE,
            attributes=['cn', 'lastKnownParent', 'sAMAccountName'],
            controls=[('1.2.840.113556.1.4.417', True, None)],
        )
        if not conn.entries:
            return False, 'Deleted object not found'

        entry = conn.entries[0]
        cn = str(entry.cn) if entry.cn else ''
        if '\n' in cn:
            cn = cn.split('\n')[0]
        if '\x0a' in cn:
            cn = cn.split('\x0a')[0]

        target_ou = new_ou_dn or (str(entry.lastKnownParent) if entry.lastKnownParent else cfg['BASE_DN'])

        # Restore: modify isDeleted to remove it and move to target OU
        new_rdn = f"CN={cn}"
        result = conn.modify_dn(
            deleted_dn,
            new_rdn,
            new_superior=target_ou,
            controls=[('1.2.840.113556.1.4.417', True, None)],
        )
        if not result:
            desc = conn.result.get('description', 'Restore failed')
            return False, desc

        # Clear isDeleted attribute
        new_dn = f"{new_rdn},{target_ou}"
        conn.modify(new_dn, {'isDeleted': [('MODIFY_DELETE', [])]})

        return True, f"Object '{cn}' restored to {target_ou}"
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
