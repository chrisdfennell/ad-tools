"""Raw attribute editor service - browse/edit any attribute on any AD object."""

from ldap3 import SUBTREE, MODIFY_REPLACE, MODIFY_DELETE
from flask import current_app

from .ad_connection import get_connection


def get_object_attributes(dn):
    """Get all attributes on an AD object by DN."""
    conn = None
    try:
        conn = get_connection()
        conn.search(
            search_base=dn,
            search_filter='(objectClass=*)',
            search_scope='BASE',
            attributes=['*'],
        )
        if not conn.entries:
            return False, 'Object not found'

        entry = conn.entries[0]
        attrs = {}
        for attr_name in entry.entry_attributes:
            raw_val = getattr(entry, attr_name)
            if raw_val and raw_val.values:
                if len(raw_val.values) == 1:
                    attrs[attr_name] = str(raw_val.value)
                else:
                    attrs[attr_name] = [str(v) for v in raw_val.values]
            else:
                attrs[attr_name] = ''

        # Sort by attribute name
        sorted_attrs = dict(sorted(attrs.items(), key=lambda x: x[0].lower()))
        obj_info = {
            'dn': str(entry.entry_dn),
            'attributes': sorted_attrs,
        }
        return True, obj_info
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def modify_object_attribute(dn, attribute, value):
    """Set or clear an attribute on an AD object."""
    conn = None
    try:
        conn = get_connection()
        if value == '' or value is None:
            # Clear the attribute
            conn.modify(dn, {attribute: [(MODIFY_DELETE, [])]})
        else:
            conn.modify(dn, {attribute: [(MODIFY_REPLACE, [value])]})

        if conn.result['result'] == 0:
            return True, f'Attribute "{attribute}" updated successfully.'
        else:
            return False, f'Failed: {conn.result["description"]} - {conn.result.get("message", "")}'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def search_objects(query, object_class='*'):
    """Search for any AD object by CN to find its DN for the attribute editor."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        ldap_filter = f'(&(objectClass={object_class})(cn=*{query}*))'
        conn.search(
            cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
            attributes=['cn', 'distinguishedName', 'objectClass', 'sAMAccountName'],
            size_limit=50,
        )

        results = []
        for entry in conn.entries:
            obj_classes = entry.objectClass.values if entry.objectClass else []
            # Determine friendly type
            if 'user' in obj_classes and 'computer' not in obj_classes:
                obj_type = 'User'
            elif 'computer' in obj_classes:
                obj_type = 'Computer'
            elif 'group' in obj_classes:
                obj_type = 'Group'
            elif 'organizationalUnit' in obj_classes:
                obj_type = 'OU'
            else:
                obj_type = 'Other'

            sam = ''
            try:
                sam = str(entry.sAMAccountName) if entry.sAMAccountName.value else ''
            except Exception:
                pass

            results.append({
                'cn': str(entry.cn),
                'dn': str(entry.entry_dn),
                'type': obj_type,
                'sam': sam,
            })
        return True, results
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
