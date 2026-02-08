"""Delegation/Permissions Viewer - read ACLs on AD objects."""

from ldap3 import SUBTREE, BASE
from flask import current_app

from .ad_connection import get_connection

# Well-known SID mappings
WELL_KNOWN_SIDS = {
    'S-1-5-32-544': 'BUILTIN\\Administrators',
    'S-1-5-32-545': 'BUILTIN\\Users',
    'S-1-5-32-548': 'BUILTIN\\Account Operators',
    'S-1-5-32-549': 'BUILTIN\\Server Operators',
    'S-1-5-32-550': 'BUILTIN\\Print Operators',
    'S-1-5-32-551': 'BUILTIN\\Backup Operators',
    'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
    'S-1-5-10': 'NT AUTHORITY\\SELF',
    'S-1-1-0': 'Everyone',
    'S-1-5-11': 'NT AUTHORITY\\Authenticated Users',
    'S-1-5-9': 'NT AUTHORITY\\Enterprise Domain Controllers',
}

# Dangerous permissions to flag
DANGEROUS_RIGHTS = [
    'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
    'WriteProperty', 'ExtendedRight', 'Self',
]


def get_delegations_on_ous():
    """Get non-inherited ACEs on all OUs (delegated permissions)."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # Get all OUs
        conn.search(
            cfg['BASE_DN'],
            '(objectClass=organizationalUnit)',
            search_scope=SUBTREE,
            attributes=['ou', 'distinguishedName', 'nTSecurityDescriptor'],
            controls=[('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x04')],
        )

        delegations = []
        for entry in conn.entries:
            ou_name = str(entry.ou) if entry.ou.value else ''
            ou_dn = str(entry.entry_dn)

            # Parse the security descriptor
            try:
                sd_raw = entry['nTSecurityDescriptor'].raw_values[0]
                aces = _parse_security_descriptor(sd_raw, conn, cfg['BASE_DN'])
                for ace in aces:
                    if not ace.get('inherited', True):
                        ace['ou_name'] = ou_name
                        ace['ou_dn'] = ou_dn
                        delegations.append(ace)
            except Exception:
                continue

        return True, delegations
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_object_acl(dn):
    """Get all ACEs on a specific object."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        conn.search(
            dn,
            '(objectClass=*)',
            search_scope=BASE,
            attributes=['distinguishedName', 'nTSecurityDescriptor', 'cn', 'ou'],
            controls=[('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x04')],
        )
        if not conn.entries:
            return False, 'Object not found'

        entry = conn.entries[0]
        obj_name = ''
        try:
            obj_name = str(entry.ou) if entry.ou.value else str(entry.cn) if entry.cn.value else dn
        except Exception:
            obj_name = dn

        try:
            sd_raw = entry['nTSecurityDescriptor'].raw_values[0]
            aces = _parse_security_descriptor(sd_raw, conn, cfg['BASE_DN'])
        except Exception as e:
            aces = []

        return True, {'dn': dn, 'name': obj_name, 'aces': aces}
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _parse_security_descriptor(sd_bytes, conn, base_dn):
    """Parse a binary Windows Security Descriptor into readable ACEs."""
    aces = []
    try:
        import struct
        # SD header: revision(1), sbz1(1), control(2), offset_owner(4),
        # offset_group(4), offset_sacl(4), offset_dacl(4) = 20 bytes
        if len(sd_bytes) < 20:
            return aces

        revision = sd_bytes[0]
        control = struct.unpack_from('<H', sd_bytes, 2)[0]
        offset_owner = struct.unpack_from('<I', sd_bytes, 4)[0]
        offset_dacl = struct.unpack_from('<I', sd_bytes, 16)[0]

        if offset_dacl == 0:
            return aces

        # DACL header: revision(1), sbz1(1), size(2), ace_count(2), sbz2(2)
        dacl_offset = offset_dacl
        if dacl_offset + 8 > len(sd_bytes):
            return aces

        dacl_revision = sd_bytes[dacl_offset]
        dacl_size = struct.unpack_from('<H', sd_bytes, dacl_offset + 2)[0]
        ace_count = struct.unpack_from('<H', sd_bytes, dacl_offset + 4)[0]

        pos = dacl_offset + 8  # Start of first ACE

        sid_cache = {}

        for i in range(min(ace_count, 200)):  # Limit to prevent runaway
            if pos + 4 > len(sd_bytes):
                break

            ace_type = sd_bytes[pos]
            ace_flags = sd_bytes[pos + 1]
            ace_size = struct.unpack_from('<H', sd_bytes, pos + 2)[0]

            if ace_size < 4 or pos + ace_size > len(sd_bytes):
                break

            inherited = bool(ace_flags & 0x10)  # INHERITED_ACE

            # ACCESS_ALLOWED_ACE (0) or ACCESS_DENIED_ACE (1)
            # ACCESS_ALLOWED_OBJECT_ACE (5) or ACCESS_DENIED_OBJECT_ACE (6)
            type_names = {0: 'Allow', 1: 'Deny', 5: 'Allow (Object)', 6: 'Deny (Object)'}
            type_name = type_names.get(ace_type, f'Type {ace_type}')

            if ace_type in (0, 1):
                # Standard ACE: mask(4) + SID
                if pos + 8 > len(sd_bytes):
                    pos += ace_size
                    continue
                mask = struct.unpack_from('<I', sd_bytes, pos + 4)[0]
                sid_bytes = sd_bytes[pos + 8:pos + ace_size]
                sid_str = _bytes_to_sid(sid_bytes)
                rights = _mask_to_rights(mask)

                principal = _resolve_sid(sid_str, sid_cache, conn, base_dn)
                aces.append({
                    'type': type_name,
                    'principal': principal,
                    'sid': sid_str,
                    'rights': rights,
                    'inherited': inherited,
                    'dangerous': any(r in DANGEROUS_RIGHTS for r in rights.split(', ')),
                })

            elif ace_type in (5, 6):
                # Object ACE: mask(4), obj_flags(4), [obj_type(16)], [inherited_obj(16)], SID
                if pos + 12 > len(sd_bytes):
                    pos += ace_size
                    continue
                mask = struct.unpack_from('<I', sd_bytes, pos + 4)[0]
                obj_flags = struct.unpack_from('<I', sd_bytes, pos + 8)[0]
                sid_offset = pos + 12
                if obj_flags & 1:
                    sid_offset += 16  # ObjectType GUID present
                if obj_flags & 2:
                    sid_offset += 16  # InheritedObjectType GUID present

                sid_bytes = sd_bytes[sid_offset:pos + ace_size]
                sid_str = _bytes_to_sid(sid_bytes)
                rights = _mask_to_rights(mask)

                principal = _resolve_sid(sid_str, sid_cache, conn, base_dn)
                aces.append({
                    'type': type_name,
                    'principal': principal,
                    'sid': sid_str,
                    'rights': rights,
                    'inherited': inherited,
                    'dangerous': any(r in DANGEROUS_RIGHTS for r in rights.split(', ')),
                })

            pos += ace_size

    except Exception:
        pass

    return aces


def _bytes_to_sid(sid_bytes):
    """Convert raw SID bytes to S-x-x-x... string."""
    try:
        import struct
        if len(sid_bytes) < 8:
            return 'S-?'
        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], byteorder='big')
        subs = []
        for i in range(min(sub_auth_count, 15)):
            offset = 8 + i * 4
            if offset + 4 > len(sid_bytes):
                break
            subs.append(struct.unpack_from('<I', sid_bytes, offset)[0])
        return f'S-{revision}-{authority}-' + '-'.join(str(s) for s in subs)
    except Exception:
        return 'S-?'


def _resolve_sid(sid_str, cache, conn, base_dn):
    """Resolve a SID to a friendly name."""
    if sid_str in cache:
        return cache[sid_str]

    # Check well-known SIDs
    if sid_str in WELL_KNOWN_SIDS:
        cache[sid_str] = WELL_KNOWN_SIDS[sid_str]
        return cache[sid_str]

    # Try to resolve via LDAP
    try:
        conn.search(base_dn, f'(objectSid={sid_str})', search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName'])
        if conn.entries:
            name = str(conn.entries[0].sAMAccountName) if conn.entries[0].sAMAccountName.value else str(conn.entries[0].cn)
            cache[sid_str] = name
            return name
    except Exception:
        pass

    cache[sid_str] = sid_str
    return sid_str


def _mask_to_rights(mask):
    """Convert an access mask to readable rights strings."""
    rights = []

    # Generic rights
    if mask & 0x10000000:
        rights.append('GenericAll')
    if mask & 0x20000000:
        rights.append('GenericExecute')
    if mask & 0x40000000:
        rights.append('GenericWrite')
    if mask & 0x80000000:
        rights.append('GenericRead')

    # Standard rights
    if mask & 0x00040000:
        rights.append('WriteDacl')
    if mask & 0x00080000:
        rights.append('WriteOwner')
    if mask & 0x00010000:
        rights.append('Delete')
    if mask & 0x00020000:
        rights.append('ReadControl')

    # DS-specific rights
    if mask & 0x00000001:
        rights.append('ReadProperty')
    if mask & 0x00000002:
        rights.append('WriteProperty')
    if mask & 0x00000004:
        rights.append('CreateChild')
    if mask & 0x00000008:
        rights.append('DeleteChild')
    if mask & 0x00000010:
        rights.append('ListContents')
    if mask & 0x00000020:
        rights.append('Self')
    if mask & 0x00000040:
        rights.append('ListObject')
    if mask & 0x00000080:
        rights.append('DeleteTree')
    if mask & 0x00000100:
        rights.append('ExtendedRight')

    if not rights:
        rights.append(f'0x{mask:08X}')
    return ', '.join(rights)
