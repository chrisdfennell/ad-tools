"""AD Schema Browser - browse objectClass and attribute definitions."""

from ldap3 import SUBTREE, BASE
from flask import current_app

from .ad_connection import get_connection


SYNTAX_MAP = {
    '2.5.5.1': 'DN',
    '2.5.5.2': 'OID',
    '2.5.5.3': 'Case-Insensitive String',
    '2.5.5.4': 'Case-Insensitive String',
    '2.5.5.5': 'Printable String (IA5)',
    '2.5.5.6': 'Numeric String',
    '2.5.5.7': 'DN + Binary',
    '2.5.5.8': 'Boolean',
    '2.5.5.9': 'Integer',
    '2.5.5.10': 'Octet String',
    '2.5.5.11': 'Generalized Time',
    '2.5.5.12': 'Unicode String',
    '2.5.5.13': 'Presentation Address',
    '2.5.5.14': 'DN + Unicode',
    '2.5.5.15': 'NT Security Descriptor',
    '2.5.5.16': 'Large Integer',
    '2.5.5.17': 'SID',
}


def _get_schema_dn(conn):
    """Get the Schema naming context from RootDSE."""
    try:
        info = conn.server.info
        return str(info.other.get('schemaNamingContext', [None])[0])
    except Exception:
        base = current_app.config['BASE_DN']
        return f"CN=Schema,CN=Configuration,{base}"


def get_object_classes(query=''):
    """Get all objectClass definitions from the schema."""
    conn = None
    try:
        conn = get_connection()
        schema_dn = _get_schema_dn(conn)

        if query:
            ldap_filter = f'(&(objectClass=classSchema)(cn=*{query}*))'
        else:
            ldap_filter = '(objectClass=classSchema)'

        conn.search(
            schema_dn, ldap_filter, search_scope=SUBTREE,
            attributes=[
                'cn', 'lDAPDisplayName', 'adminDescription',
                'objectClassCategory', 'subClassOf',
                'mustContain', 'mayContain',
                'systemMustContain', 'systemMayContain',
                'defaultSecurityDescriptor',
            ],
        )

        category_map = {0: 'Abstract', 1: 'Structural', 2: 'Auxiliary'}
        classes = []
        for entry in conn.entries:
            def _safe(attr, e=entry):
                try:
                    return e[attr].value
                except Exception:
                    return None

            def _safe_list(attr, e=entry):
                try:
                    val = e[attr].value
                    if isinstance(val, list):
                        return val
                    return [val] if val else []
                except Exception:
                    return []

            cat = int(_safe('objectClassCategory') or 0)
            classes.append({
                'cn': str(_safe('cn') or ''),
                'ldap_name': str(_safe('lDAPDisplayName') or ''),
                'description': str(_safe('adminDescription') or ''),
                'category': category_map.get(cat, f'Unknown ({cat})'),
                'parent': str(_safe('subClassOf') or ''),
                'must_contain': _safe_list('mustContain') + _safe_list('systemMustContain'),
                'may_contain': _safe_list('mayContain') + _safe_list('systemMayContain'),
            })

        classes.sort(key=lambda c: c['ldap_name'].lower())
        return True, classes
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_attribute_definitions(query=''):
    """Get attribute definitions from the schema."""
    conn = None
    try:
        conn = get_connection()
        schema_dn = _get_schema_dn(conn)

        if query:
            ldap_filter = f'(&(objectClass=attributeSchema)(|(cn=*{query}*)(lDAPDisplayName=*{query}*)))'
        else:
            ldap_filter = '(objectClass=attributeSchema)'

        conn.search(
            schema_dn, ldap_filter, search_scope=SUBTREE,
            attributes=[
                'cn', 'lDAPDisplayName', 'adminDescription',
                'attributeSyntax', 'isSingleValued',
                'searchFlags', 'isMemberOfPartialAttributeSet',
                'systemOnly', 'rangeLower', 'rangeUpper',
            ],
        )

        attrs = []
        for entry in conn.entries:
            def _safe(attr, e=entry):
                try:
                    return e[attr].value
                except Exception:
                    return None

            syntax_oid = str(_safe('attributeSyntax') or '')
            search_flags = int(_safe('searchFlags') or 0)

            attrs.append({
                'cn': str(_safe('cn') or ''),
                'ldap_name': str(_safe('lDAPDisplayName') or ''),
                'description': str(_safe('adminDescription') or ''),
                'syntax': SYNTAX_MAP.get(syntax_oid, syntax_oid),
                'syntax_oid': syntax_oid,
                'single_valued': bool(_safe('isSingleValued')),
                'indexed': bool(search_flags & 1),
                'gc_replicated': bool(_safe('isMemberOfPartialAttributeSet')),
                'system_only': bool(_safe('systemOnly')),
                'range_lower': _safe('rangeLower'),
                'range_upper': _safe('rangeUpper'),
            })

        attrs.sort(key=lambda a: a['ldap_name'].lower())
        return True, attrs
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
